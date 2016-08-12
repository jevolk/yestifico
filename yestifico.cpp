/** 
 *  COPYRIGHT 2014 (C) Jason Volk
 *  COPYRIGHT 2014 (C) Svetlana Tkachenko
 *
 *  DISTRIBUTED UNDER THE GNU GENERAL PUBLIC LICENSE (GPL) (see: LICENSE)
 */

#include <openssl/hmac.h>
#include "ircbot/bot.h"
#include "urldecode2.h"

using std::for_each;
namespace ph = std::placeholders;
using namespace irc::bot;


Bot *bot;
boost::asio::io_service *ios;
std::string channame;

std::condition_variable cond;            // rang when clients and acceptor callbacks have canceled
std::list<struct client *> clients;
std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;

std::string getline_crlf(std::istream &in);



struct message
{
	std::string cmd;                     // HTTP/1.1 POST ...
	std::string src;                     // github/travis/...
	std::string sig;                     // github hmac
	std::string event;                   // push/ping/...
	size_t content_length;
	Adoc doc;

	bool validate(const std::string &content);

	message(std::istream &in);
};


message::message(std::istream &in)
:cmd
{
	getline_crlf(in)
}
,content_length
{
	0
}
{
	// parse HTTP
	if(cmd.empty())
		throw Assertive("No HTTP command");

	// parse headers
	std::string line(getline_crlf(in));
	for(; !line.empty(); line = getline_crlf(in))
	{
		std::cout << "HEADER " << line << std::endl;
		const auto header(split(line, ": "));
		switch(hash(tolower(header.first)))
		{
			case hash("content-length"):
				content_length = lex_cast<size_t>(header.second);
				continue;

			case hash("x-github-event"):
				src = "github";
				event = header.second;
				continue;

			case hash("x-hub-signature"):
			{
				const auto kv(split(header.second, "="));
				if(kv.first != "sha1")
					throw Assertive("Unsupported signature type");

				sig = kv.second;
				continue;
			}
		}
	}

	if(!content_length)
		throw Assertive("content-length missing");

	// parse body
	std::string content(getline_crlf(in));
	std::cout << "BODY " << content << std::endl;

	if(content_length != content.size())
		throw Assertive("content-length mismatch")
		                << " expecting: " << content_length
		                << " got: " << content.size();

	switch(hash(src))
	{
		case hash("travis"):
		{
			std::unique_ptr<char[]> buf(new char[1024 * 1024 * 5]);
			memset(buf.get(), 0x0, 1024 * 1024 * 5);
			urldecode2(buf.get(), split(content, "=").second.c_str());
			doc = std::string(buf.get());
			break;
		}

		default:
		case hash("github"):
		{
			if(!validate(content))
				throw Assertive("Invalid content");

			doc = content;
			break;
		}
	}
}


bool message::validate(const std::string &content)
{
	const auto &opts(bot->opts);
	if(!opts.has("yestifico-secret"))
		return true;

	if(sig.empty())
		return false;

	uint8_t buf[20];
	const auto secret(opts["yestifico-secret"]);
	HMAC(EVP_sha1(), secret.data(), secret.size(), (const uint8_t *)content.data(), content.size(), buf, NULL);

	char hmac[41];
	for(size_t i(0); i < sizeof(buf); i++)
		sprintf(hmac + i * 2, "%02x", buf[i]);

	std::cout << "HMAC: " << hmac << std::endl;
	return sig == hmac;
}


struct client
:std::enable_shared_from_this<client>
{
	boost::asio::ip::tcp::socket socket;
	boost::asio::streambuf in, out;
	decltype(clients)::iterator clit;

	void respond(const std::string &status = "200 OK");

	void handle_github_status(message &message);
	void handle_github_push(message &message);
	void handle_github_ping(message &message);
	void handle_github(message &message);
	void handle_travis(message &message);
	void parse(std::istream &input);
	void handle(const boost::system::error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void set_handler();

	client();
	~client();
};


client::client()
:socket
{
	*ios
}
,in
{
	1024 * 1024 * 5     // GH says they cap webhooks at 5 MiB
}
,out
{
	65536               // Arbitrary send buffer max size
}
,clit
{
	clients.emplace(end(clients), this)
}
{
	in.prepare(in.max_size());
	out.prepare(out.max_size());
}


client::~client()
{
	clients.erase(clit);
}


void client::set_handler()
{
	static const auto terminator
	{
		"\r\n\r\n"
	};

	const auto callback
	{
		std::bind(&client::handle, this, ph::_1, ph::_2, shared_from_this())
	};

	async_read_until(socket, in, terminator, callback);
}


void client::handle(const boost::system::error_code &ec,
                    size_t avail,
                    std::shared_ptr<client>)
noexcept try
{
	const std::lock_guard<Bot> lock(*bot);
	switch(ec.value())
	{
		using namespace boost::system::errc;

		case success:                     break;
		case boost::asio::error::eof:     return;
		case operation_canceled:
			cond.notify_all();
			return;

		default:
			throw boost::system::error_code(ec);
	}

	const scope reset([this, &avail]
	{
		in.consume(avail);
		set_handler();
	});

	std::istream in(&this->in);
	parse(in);
	respond();
}
catch(const std::exception &e)
{
	const std::lock_guard<Bot> lock(*bot);
	auto &chan(bot->chans.get(channame));

	if(socket.is_open())
		chan << "client[" << socket.remote_endpoint() << "] ";

	chan << "error: " << e.what() << chan.flush;
}


void client::parse(std::istream &in)
{
	auto &chan(bot->chans.get(channame));
	const scope reset([&chan]
	{
		// Ensure no partial writes to the channel stream when interrupted by exception
		if(std::current_exception())
			chan.clear();
	});

	message message(in);
	switch(hash(message.src))
	{
		case hash("github"):    handle_github(message);   break;
		case hash("travis"):    handle_travis(message);   break;
		default:
			throw Assertive("unknown webhook source");
	}

	chan << chan.flush;
}


void client::handle_travis(message &message)
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(message.doc);

	chan << BOLD << doc["repository.owner_name"] << "/" << doc["repository.name"] << OFF;

	for(const auto &p : doc.get_child("matrix", Adoc{}))
	{
		const Adoc &vm(p.second.get_child("", Adoc{}));
		std::cout << vm << std::endl;
		if(vm["status_message"] == "Still Failing")
			chan << "[" << BG::RED << " " << OFF << "]";
	}

	return;
}


void client::handle_github(message &message)
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(message.doc);

	if(doc.has("repository.full_name"))
		chan << BOLD << doc["repository.full_name"] << OFF;

	if(doc.has_child("pusher"))
		chan << " by " << doc["pusher.name"];
	else if(doc.has_child("sender"))
		chan << " by " << doc["sender.login"];

	chan << " " << message.event;

	switch(hash(message.event))
	{
		case hash("ping"):         handle_github_ping(message);     break;
		case hash("push"):         handle_github_push(message);     break;
		case hash("status"):       handle_github_status(message);   break;
		default:                                                    break;
	}
}


void client::handle_github_ping(message &message)
{
	auto &chan(bot->chans.get(channame));
	auto &doc(message.doc);

	chan << doc["id"];
}


void client::handle_github_push(message &message)
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(message.doc);

	if(doc["forced"] == "true")
		chan << " (rebase)";

	if(doc.has("head_commit.id"))
		chan << " @ " << BOLD << FG::CYAN << doc["head_commit.id"] << OFF;

	chan << chan.flush; // Flush to start new lines for the commits

	for(const auto &p : doc.get_child("commits", Adoc{}))
	{
		const Adoc &commit(p.second.get_child("", Adoc{}));

		chan << "*";
		chan << " " << commit["author.name"];
		if(commit["committer.email"] != commit["author.email"])
			chan << " via " << commit["committer.name"];

		chan << " (" << commit["url"] << ")";
		const auto cm(split(commit["message"], "\n").first);
		chan << " " << UNDER2 << cm << OFF;
		chan << chan.flush;
	}
}


void client::handle_github_status(message &message)
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(message.doc);

	switch(hash(doc["context"]))
	{
		case hash("continuous-integration/travis-ci/push"):
		{
			if(doc["state"] == "pending")
			{
				// Ignore the pending message by clearing the stream
				chan.Stream::clear();
				break;
			}

			if(doc["state"] == "error")
				chan << " " << FG::RED;

			if(doc["state"] == "failure")
				chan << " " << FG::LRED;

			if(doc["state"] == "success")
				chan << " " << FG::GREEN;

			chan << doc["description"] << OFF;

			if(doc.has("target_url"))
				chan << " (" << doc["target_url"] << ")";

			break;
		}

		default:
			chan << "context: " << doc["context"] << " unhandled";
			break;
	}
}


void client::respond(const std::string &status)
{
	std::ostream out(&this->out);
	out << "HTTP/1.1 " << status << "\r\n";
	out << "Content-Type: application/json\r\n";
	out << "Content-Length: 0\r\n";
	out << "\r\n";
	out << "\r\n";

	const auto bufs(this->out.data());
	const auto sent(socket.send(bufs));
	this->out.consume(sent);
}


void set_accept();
void handle_accept(const boost::system::error_code &ec,
                   std::shared_ptr<client> c)
try
{
	using namespace boost::system::errc;

	const std::lock_guard<Bot> lock(*bot);
	const scope reset([&ec]
	{
		// Always continue with the next accept client unless shutdown
		if(ec != operation_canceled)
			set_accept();
	});

	switch(ec.value())
	{
		case success:
			break;

		case operation_canceled:
			cond.notify_all();
			return;

		default:
			throw Exception(ec.message());
	}

	c->set_handler();
}
catch(const std::exception &e)
{
	const std::lock_guard<Bot> lock(*bot);
	auto &chan(bot->chans.get(channame));
	chan << "acceptor: error: " << e.what() << chan.flush;
}


void set_accept()
{
	auto client(std::make_shared<client>());
	const auto callback(std::bind(&handle_accept, ph::_1, client));
	acceptor->async_accept(client->socket, callback);
}



void handle_privmsg(const Msg &msg,
                    Chan &chan,
                    User &user)
try
{

}
catch(const Assertive &e)
{
	user << chan << "Internal Error: " << e << user.flush;
	throw;
}
catch(const std::exception &e)
{
	user << chan << "Failed: " << e.what() << user.flush;
}


extern "C"
void module_init(Bot *const bot)
noexcept
{
	::bot = bot;
	::ios = &bot->sess.get_ios();

	const std::lock_guard<Bot> lock(*bot);
	bot->set_tls_context();
	bot->events.chan_user.add("PRIVMSG",
	                          std::bind(&handle_privmsg, ph::_1, ph::_2, ph::_3),
	                          handler::RECURRING);

	const auto &opts(bot->opts);
	const auto bind_port
	{
		opts.has("yestifico-port")? opts.get<uint16_t>("yestifico-port") : 6699
	};

	const boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), bind_port);
	acceptor.reset(new boost::asio::ip::tcp::acceptor(*ios, ep, true));
	set_accept();

	channame = opts.has("yestifico-chan")? opts["yestifico-chan"] : "#charybdis";

	std::cout << "yestifico listening: " << ep << std::endl;
}


extern "C"
void module_fini(Bot *const bot)
noexcept
{
	std::unique_lock<std::mutex> lock(*bot);
	if(acceptor->is_open())
		acceptor->close();

	for(auto *const &client : clients)
		if(client->socket.is_open())
			client->socket.close();

	cond.wait(lock, []
	{
		return clients.empty();
	});

	bot->events.chan_user.clear(handler::Prio::USER);
}


std::string getline_crlf(std::istream &in)
{
	std::string ret;
	std::getline(in, ret);
	if(ret.back() == '\r')
		ret.pop_back();

	return ret;
}

/** 
 *  COPYRIGHT 2016 (C) Jason Volk
 *
 *  DISTRIBUTED UNDER THE GNU GENERAL PUBLIC LICENSE >= VERSION 1
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
	size_t content_length = 0;
	size_t head_size = 0;
	Adoc doc;

	bool validate(const std::string &content);
	void parse_body(std::istream &in);
	void parse_head(std::istream &in);
};


void message::parse_head(std::istream &in)
{
	// parse HTTP
	cmd = getline_crlf(in);

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

			case hash("travis-repo-slug"):
				src = "travis";
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
}


void message::parse_body(std::istream &in)
{
	std::unique_ptr<char[]> buf(new char[content_length + 1]);
	memset(buf.get(), 0x0, content_length + 1);
	in.read(buf.get(), content_length);
	std::cout << "BODY " << std::string(buf.get()) << std::endl;

	switch(hash(src))
	{
		case hash("travis"):
		{
			std::unique_ptr<char[]> buf2(new char[1024 * 1024 * 5]);
			urldecode2(buf2.get(), split(buf.get(), "=").second.c_str());
			doc = std::string(buf2.get());
			break;
		}

		default:
		case hash("github"):
		{
			if(!validate(buf.get()))
				throw Assertive("Invalid content");

			doc = std::string(buf.get());
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
	boost::asio::streambuf in, out;         // socket buffers
	decltype(clients)::iterator clit;       // pointer into the client list
	std::unique_ptr<message> msg;           // current message state

	void error_to_chan(const std::exception &e);
	void respond(const std::string &status = "200 OK");

	void handle_github_pull_request();
	void handle_github_status();
	void handle_github_push();
	void handle_github_ping();
	void handle_github();
	void handle_travis();

	size_t handle_xfer(const boost::system::error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void handle_body(const boost::system::error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void handle_head(const boost::system::error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void set_body_handler();
	void set_head_handler();

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
,msg
{
	std::make_unique<message>()
}
{
}


client::~client()
{
	clients.erase(clit);
}


void client::set_head_handler()
{
	static const auto terminator
	{
		"\r\n\r\n"
	};

	const auto callback
	{
		std::bind(&client::handle_head, this, ph::_1, ph::_2, shared_from_this())
	};

	async_read_until(socket, in, terminator, callback);
}


void client::set_body_handler()
{
	const auto callback
	{
		std::bind(&client::handle_body, this, ph::_1, ph::_2, shared_from_this())
	};

	const auto condition
	{
		std::bind(&client::handle_xfer, this, ph::_1, ph::_2, shared_from_this())
	};

	async_read(socket, in, condition, callback);
}


void client::handle_head(const boost::system::error_code &ec,
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

	std::istream in(&this->in);
	msg->parse_head(in);

	msg->head_size = avail;
	if(msg->content_length + avail >= this->in.max_size())
		return;

	set_body_handler();
}
catch(const std::exception &e)
{
	const std::lock_guard<Bot> lock(*bot);
	error_to_chan(e);
}


size_t client::handle_xfer(const boost::system::error_code &ec,
                           size_t avail,
                           std::shared_ptr<client>)
noexcept
{
	return avail >= msg->content_length - msg->head_size? 0 : msg->content_length - avail;
}


void client::handle_body(const boost::system::error_code &ec,
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

	auto &chan(bot->chans.get(channame));
	const scope reset([this, &avail, &chan]
	{
		if(std::current_exception())
			chan.clear();

		msg.reset();
		set_head_handler();
	});

	std::istream in(&this->in);
	msg->parse_body(in);
	switch(hash(msg->src))
	{
		case hash("github"):    handle_github();   break;
		case hash("travis"):    handle_travis();   break;
		default:
			throw Assertive("unknown webhook source");
	}

	chan << chan.flush;
	respond();
}
catch(const std::exception &e)
{
	const std::lock_guard<Bot> lock(*bot);
	error_to_chan(e);
}


void client::handle_travis()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);
	std::cout << doc << std::endl;

	if(doc.has("state") && doc["state"] == "started")
		return;

	chan << BOLD << doc["repository.owner_name"] << "/" << doc["repository.name"] << OFF;

	const auto commit
	{
		doc.has("commit") && doc["commit"] != "null"?             doc["commit"]:
		doc.has("head_commit") && doc["head_commit"] != "null"?   doc["head_commit"]:
		                                                          std::string{}
	};

	if(!commit.empty())
		chan << " " << commit.substr(0, 8);

	chan << " " << doc["number"];

	chan << BOLD << " |" << OFF;
	for(const auto &p : doc.get_child("matrix", Adoc{}))
	{
		const Adoc &vm(p.second.get_child("", Adoc{}));
		std::cout << vm << std::endl;
		switch(hash(vm["state"]))
		{
			case hash("started"):
				chan << BOLD << FG::WHITE << BG::CYAN_BLINK << "S" << OFF;
				break;

			case hash("received"):
				chan << BOLD << FG::WHITE << BG::LGRAY_BLINK << "R" << OFF;
				break;

			case hash("queued"):
				chan << BOLD << FG::WHITE << BG::CYAN << "Q" << OFF;
				break;

			case hash("created"):
				chan << BOLD << FG::WHITE << BG::LGRAY << "C" << OFF;
				break;

			case hash("finished"):
				if(vm["result"] == "0")  // "0" for success
				{
					chan << BOLD << FG::WHITE << BG::GREEN << "+" << OFF;
					break;
				}

			case hash("failed"):
				chan << BOLD << FG::WHITE << BG::RED << "-" << OFF;
				break;

			case hash("error"):
				chan << BOLD << FG::WHITE << BG::ORANGE_BLINK << "X" << OFF;
				break;

			default:
				chan  << "?";
				break;
		}
	}
	chan << BOLD << "|" << OFF;

	if(doc.has("duration") && doc["duration"] != "null")
		chan << " in " << secs_cast(secs_cast(doc["duration"]));

	if(doc.has("message"))
	{
		const auto cm(split(doc["message"], "\n").first);
		chan << " " << UNDER2 << cm << OFF;
	}

	chan << chan.flush;
}


void client::handle_github()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	if(doc.has("repository.full_name"))
		chan << BOLD << doc["repository.full_name"] << OFF;

	const auto commit
	{
		doc.has("sha")?              doc["sha"]:
		doc.has("commit.sha")?       doc["commit.sha"]:
		doc.has("head.commit")?      doc["head.commit"]:
		doc.has("head_commit.id")?   doc["head_commit.id"]:
		doc.has("commit")?           doc["commit"]:
		                             std::string{}
	};

	if(!commit.empty())
	{
		chan << " ";
		switch(hash(msg->event))
		{
			case hash("push"):           chan << FG::ORANGE;             break;
			case hash("pull_request"):   chan << BOLD << FG::MAGENTA;    break;
		}

		chan << commit.substr(0, 8) << OFF;
	}

	if(doc.has("ref"))
		chan << " " << doc["ref"];

	chan << " " << msg->event;

	if(doc.has_child("pusher"))
		chan << " by " << doc["pusher.name"];
	else if(doc.has_child("sender"))
		chan << " by " << doc["sender.login"];

	switch(hash(msg->event))
	{
		case hash("ping"):           handle_github_ping();           break;
		case hash("push"):           handle_github_push();           break;
		case hash("status"):         handle_github_status();         break;
		case hash("pull_request"):   handle_github_pull_request();   break;
		default:                                                     break;
	}
}


void client::handle_github_ping()
{
	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " " << doc["hook.id"] << " \"" << doc["zen"] << "\"";
}


void client::handle_github_push()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	if(doc["forced"] == "true")
		chan << " (rebase)";

	const auto commits(doc.get_child("commits", Adoc{}));
	const auto num(std::distance(begin(commits), end(commits)));
	chan << " " << num << " commits";
	if(num > 15)
		chan << FG::LGRAY << "(please be patient)" << OFF;

	chan << chan.flush; // Flush to start new lines for the commits

	for(const auto &p : commits)
	{
		const Adoc &commit(p.second.get_child("", Adoc{}));

		chan << "|";

		auto url(commit["url"]);
		const auto last_slash_pos(url.find_last_of('/'));
		url = url.substr(0, last_slash_pos + 9);
		chan << " " << url;

		chan << " " << commit["author.name"];
		if(commit["committer.email"] != commit["author.email"])
			chan << " via " << commit["committer.name"];

		const auto cm(split(commit["message"], "\n").first);
		chan << " " << UNDER2 << cm << OFF;
		chan << chan.flush;
	}
}


void client::handle_github_status()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " ";

	switch(hash(doc["context"]))
	{
		case hash("continuous-integration/appveyor/pr"):
		case hash("continuous-integration/appveyor/branch"):
		case hash("continuous-integration/travis-ci/pr"):
		case hash("continuous-integration/travis-ci/push"):
		{
			if(doc["state"] == "pending")
			{
				// Ignore the pending message by clearing the stream
				chan.Stream::clear();
				break;
			}

			if(doc["state"] == "error")
				chan << FG::RED;

			if(doc["state"] == "failure")
				chan << FG::LRED;

			if(doc["state"] == "success")
				chan << FG::GREEN;

			chan << doc["description"] << OFF;

			if(doc.has("target_url"))
			{
				const auto commit(doc["commit"].substr(0, 8));
				chan << commit << " (" << doc["target_url"] << ")";
			}

			break;
		}

		default:
			chan << "context: " << doc["context"] << " unhandled";
			break;
	}
}


void client::handle_github_pull_request()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " " << doc["action"];
	chan << " " << BOLD << "#" << doc["number"] << OFF;
	chan << " " << UNDER2 << doc["pull_request.title"] << OFF;

	chan << " ";
	switch(hash(doc["mergeable"]))
	{
		default:
		case hash("null"):
			//chan << BOLD << FG::BLACK << BG::LGRAY << "TESTING IF MERGEABLE" << OFF;
			break;

		case hash("true"):
			chan << BOLD << FG::WHITE << BG::GREEN_BLINK << "MERGEABLE" << OFF;
			break;

		case hash("false"):
			chan << BOLD << FG::WHITE << BG::RED << "NOT MERGEABLE" << OFF;
			break;
	}

	if(doc["merged"] == "true")
		chan << " " << BOLD << FG::WHITE << BG::GREEN << "MERGED" << OFF;

	if(doc.has("merged_by"))
		chan << " by " << BOLD << doc["merged_by.login"] << OFF;

	if(doc.has("additions"))
		chan << " " << BOLD << doc["additions"] << " " << FG::GREEN << "++" << OFF;

	if(doc.has("deletions"))
		chan << " " << BOLD << doc["deletions"] << " " << FG::RED << "--" << OFF;

	if(doc.has("changed_files"))
		chan << " " << BOLD << doc["changed_files"] << " " << FG::LGRAY << " files" << OFF;

	chan << chan.flush;
}


void client::respond(const std::string &status)
{
	this->out.prepare(out.max_size());
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


void client::error_to_chan(const std::exception &e)
{
	if(!bot->chans.has(channame))
		return;

	auto &chan(bot->chans.get(channame));

	if(socket.is_open())
		chan << "client[" << socket.remote_endpoint() << "] ";

	chan << "error: " << e.what() << chan.flush;
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

	c->set_head_handler();
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

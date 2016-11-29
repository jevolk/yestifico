/** 
 *  COPYRIGHT 2016 (C) Jason Volk
 *
 *  DISTRIBUTED UNDER THE GNU GENERAL PUBLIC LICENSE >= VERSION 1
 */

#include <openssl/hmac.h>
#include <boost/asio/ssl.hpp>
#include "ircbot/bot.h"
#include "urldecode2.h"

namespace ph = std::placeholders;
namespace ip = boost::asio::ip;
using std::for_each;
using boost::system::error_code;
using namespace irc::bot;


Bot *bot;
boost::asio::io_service *ios;
std::string channame;

std::condition_variable cond;            // rang when clients and acceptor callbacks have canceled
std::list<struct client *> clients;

std::unique_ptr<ip::tcp::acceptor> acceptor;
std::unique_ptr<boost::asio::ssl::context> sslctx;

std::string getline_crlf(std::istream &in);
bool errored(const error_code &ec);


struct message
{
	std::string cmd;                     // HTTP/1.1 POST ...
	std::string src;                     // github/travis/...
	std::string sig;                     // github hmac
	std::string event;                   // push/ping/...
	std::string status;                  // 200 OK ...
	size_t content_length = 0;
	Adoc doc;

	bool validate(const std::string &content);
	void parse_body(std::istream &in, const bool &validate = true);
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
			case hash("status"):
				status = tolower(header.second);
				continue;

			case hash("content-length"):
				content_length = lex_cast<size_t>(header.second);
				continue;

			case hash("x-github-event"):
				src = "github";
				event = header.second;
				continue;

			case hash("hook-source"):
				src = header.second;
				continue;

			case hash("travis-repo-slug"):
				src = "travis";
				continue;

			case hash("hook-secret"):
				if(header.second != bot->opts["yestifico-secret"])
					throw Exception("bad secret key");
				continue;

			case hash("x-hub-signature"):
			{
				const auto kv(split(header.second, "="));
				if(kv.first != "sha1")
					throw Assertive("Unsupported signature type");

				sig = kv.second;
				continue;
			}

			case hash("server"):
				switch(hash(tolower(header.second)))
				{
					case hash("github.com"):
						src = "github";
						break;
				}
				continue;
		}
	}
}


void message::parse_body(std::istream &in, const bool &validate)
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

		case hash("github"):
		{
			if(validate && !this->validate(buf.get()))
				throw Assertive("Invalid content");

			doc = std::string(buf.get());
			break;
		}

		default:
			break;
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
	ip::tcp::socket socket;
	boost::asio::ssl::stream<ip::tcp::socket> sslstream;
	boost::asio::streambuf in;              // socket buffers
	decltype(clients)::iterator clit;       // pointer into the client list
	std::unique_ptr<message> msg;           // current message state
	std::string request;

	void error_to_chan(const std::exception &e);

	void send(const std::string &data);
	void respond(const std::string &status = "200 OK");

	void handle_github_create();
	void handle_github_issue_comment();
	void handle_github_issues();
	void handle_github_commit_comment();
	void handle_github_pull_request();
	void handle_github_status();
	void handle_github_delete();
	void handle_github_push();
	void handle_github_ping();

	void handle_github_response_error();
	void handle_github_response();
	void handle_github_event();
	void handle_github();

	void handle_travis();

	void handle_appveyor();

	void handle_handshake(const error_code &ec, std::shared_ptr<client>) noexcept;
	void handle_connect(const error_code &ec, std::shared_ptr<client>) noexcept;
	void handle_resolve(const error_code &ec, ip::tcp::resolver::iterator, std::shared_ptr<client>) noexcept;
	size_t handle_xfer(const error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void handle_body(const error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void handle_head(const error_code &ec, size_t avail, std::shared_ptr<client>) noexcept;
	void set_body_handler();
	void set_head_handler();

	// connect and make request
	void operator()(const std::string &host, const std::string &request);

	client();
	~client();
};


client::client()
:socket
{
	*ios
}
,sslstream
{
	*ios, *sslctx
}
,in
{
	1024 * 1024 * 5     // GH says they cap webhooks at 5 MiB
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


void client::operator()(const std::string &host,
                        const std::string &request)
{
	if(sslstream.lowest_layer().is_open())
	{
		set_head_handler();
		send(request);
		return;
	}

	this->request = request;
	ip::tcp::resolver resolver(*ios);
	const ip::tcp::resolver::query query(host, "https");
	//const auto cb(std::bind(&client::handle_resolve, this, ph::_1, ph::_2, shared_from_this()));
	//resolver.async_resolve(query, cb);

	const auto it(resolver.resolve(query));
	const auto cb(std::bind(&client::handle_connect, this, ph::_1, shared_from_this()));
	boost::asio::async_connect(sslstream.lowest_layer(), it, cb);
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

	if(socket.is_open())
		async_read_until(socket, in, terminator, callback);
	else if(sslstream.lowest_layer().is_open())
		async_read_until(sslstream, in, terminator, callback);
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

	if(socket.is_open())
		async_read(socket, in, condition, callback);
	else if(sslstream.lowest_layer().is_open())
		async_read(sslstream, in, condition, callback);
}


void client::handle_resolve(const error_code &ec,
                            ip::tcp::resolver::iterator it,
                            std::shared_ptr<client>)
noexcept try
{
	if(errored(ec))
		return;

	const std::lock_guard<Bot> lock(*bot);
	if(it == ip::tcp::resolver::iterator())
	{
		std::cerr << "handle_resolve(): got nothing." << std::endl;
		return;
	}

	const ip::tcp::endpoint ep(*it);
	std::cout << "resolved: " << ep << std::endl;

	const auto cb(std::bind(&client::handle_connect, this, ph::_1, shared_from_this()));
	boost::asio::async_connect(sslstream.lowest_layer(), it, cb);
}
catch(const std::exception &e)
{
	std::cerr << "handle_resolve: " << e.what() << std::endl;
}
catch(...)
{
	std::cerr << "handle_resolve: unknown exception!" << std::endl;
}


void client::handle_connect(const error_code &ec,
                            std::shared_ptr<client>)
noexcept try
{
	if(errored(ec))
		return;

	const std::lock_guard<Bot> lock(*bot);
	auto &sock(sslstream.lowest_layer());
	sock.set_option(ip::tcp::no_delay(true));
	sslstream.set_verify_mode(boost::asio::ssl::verify_none);
	//sslstream.set_verify_mode(boost::asio::ssl::verify_peer);
	sslstream.set_verify_callback(boost::asio::ssl::rfc2818_verification("api.github.com"));

	const auto cb(std::bind(&client::handle_handshake, this, ph::_1, shared_from_this()));
	sslstream.async_handshake(boost::asio::ssl::stream_base::client, cb);
	std::cout << "connected: " << std::endl;
}
catch(const std::exception &e)
{
	std::cerr << "handle_connect: " << e.what() << std::endl;
}
catch(...)
{
	std::cerr << "handle_connect: unknown exception!" << std::endl;
}


void client::handle_handshake(const error_code &ec,
                              std::shared_ptr<client>)
noexcept try
{
	if(errored(ec))
		return;

	const std::lock_guard<Bot> lock(*bot);
	set_head_handler();
	send(request);
}
catch(const std::exception &e)
{
	std::cerr << "handle_handshake: " << e.what() << std::endl;
}
catch(...)
{
	std::cerr << "handle_handshake: unknown exception!" << std::endl;
}


void client::handle_head(const error_code &ec,
                         size_t avail,
                         std::shared_ptr<client>)
noexcept try
{
	if(errored(ec))
		return;

	const std::lock_guard<Bot> lock(*bot); try
	{
		std::istream in(&this->in);
		msg->parse_head(in);
		if(msg->content_length + avail >= this->in.max_size())
			return;

		if(msg->content_length)
			set_body_handler();
	}
	catch(const std::exception &e)
	{
		error_to_chan(e);
	}
}
catch(const std::exception &e)
{
	std::cerr << "handle_head: " << e.what() << std::endl;
}
catch(...)
{
	std::cerr << "handle_head: unknown exception!" << std::endl;
}


size_t client::handle_xfer(const error_code &ec,
                           size_t avail,
                           std::shared_ptr<client>)
noexcept try
{
	if(ec == boost::asio::error::eof || errored(ec))
		return 0;

	if(avail >= msg->content_length)
		return 0;

	return msg->content_length - in.size();
}
catch(const std::exception &e)
{
	std::cerr << "handle_xfer: " << e.what() << std::endl;
	return 0;
}
catch(...)
{
	std::cerr << "handle_xfer: unknown exception!" << std::endl;
	return 0;
}


void client::handle_body(const error_code &ec,
                         size_t avail,
                         std::shared_ptr<client>)
noexcept try
{
	if(errored(ec))
		return;

	const std::lock_guard<Bot> lock(*bot);
	auto &chan(bot->chans.get(channame));
	const scope reset([this, &avail, &chan]
	{
		if(std::current_exception())
			chan.clear();

		msg.reset();
		set_head_handler();
	});

	std::istream in(&this->in);
	const bool validate(socket.is_open()); // hack check: no validation on the ssl socket (plaintext socket is closed)
	msg->parse_body(in, validate);
	switch(hash(msg->src))
	{
		case hash("github"):      handle_github();     break;
		case hash("travis"):      handle_travis();     break;
		case hash("appveyor"):    handle_appveyor();   break;
		default:
			throw Assertive("unknown webhook source");
	}
}
catch(const std::exception &e)
{
	const std::lock_guard<Bot> lock(*bot);
	error_to_chan(e);
}
catch(...)
{
	std::cerr << "handle_body: unknown exception!" << std::endl;
}


void client::handle_appveyor()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);
	//std::cout << doc << std::endl;
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
	respond();
}


void client::handle_github()
{
	using namespace colors;

	if(msg->event.empty())
	{
		handle_github_response();
		return;
	}

	handle_github_event();
	respond();
}


void client::handle_github_response()
{
	using namespace colors;

	const auto status(tokens(msg->status).at(0));
	const auto code(lex_cast<short>(status));
	if(code < 200 || code >= 300)
	{
		handle_github_response_error();
		return;
	}

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	std::stringstream ss;
	ss << doc;
	chan << (ss.str().substr(0, 256)) << chan.flush;
/*
	chan << doc["id"] << " " << doc["created_at"];

	if(doc.has("repo.name"))
		chan << BOLD << doc["repo.name"] << OFF;

	if(doc.has("type"))
		chan << " " << doc["type"];

	if(doc.has("actor.login"))
		chan << " by " << doc["actor.login"];

	chan << chan.flush;
*/
}


void client::handle_github_response_error()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	if(!doc.has("message"))
		return;

	chan << doc["message"];

	if(doc.has("documentation_url"))
		chan << " (" << doc["documentation_url"] << ")";

	chan << chan.flush;
}


void client::handle_github_event()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	if(doc.has("repository.full_name"))
		chan << BOLD << doc["repository.full_name"] << OFF;

	const auto commit
	{
		doc.has("sha")?               doc["sha"]:
		doc.has("commit.sha")?        doc["commit.sha"]:
		doc.has("head.commit")?       doc["head.commit"]:
		doc.has("head_commit.id")?    doc["head_commit.id"]:
		doc.has("comment.commit_id")? doc["comment.commit_id"]:
		doc.has("commit")?            doc["commit"]:
		                              std::string{}
	};

	const auto number
	{
		doc.has("issue.number")?      doc["issue.number"]:
		doc.has("number")?            doc["number"]:
		                              std::string{}
	};

	if(!commit.empty())
	{
		chan << " ";
		switch(hash(msg->event))
		{
			case hash("push"):           chan << BOLD << FG::ORANGE;     break;
			case hash("pull_request"):   chan << BOLD << FG::MAGENTA;    break;
		}

		chan << commit.substr(0, 8) << OFF;
	}

	if(!number.empty())
		chan << " " << BOLD << "#" << number << OFF;
	else
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
		case hash("delete"):         handle_github_delete();         break;
		case hash("pull_request"):   handle_github_pull_request();   break;
		case hash("commit_comment"): handle_github_commit_comment(); break;
		case hash("issues"):         handle_github_issues();         break;
		case hash("issue_comment"):  handle_github_issue_comment();  break;
		case hash("create"):         handle_github_create();         break;
		default:                                                     break;
	}

	chan << chan.flush;
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

	const auto commits(doc.get_child("commits", Adoc{}));
	const auto num(std::distance(begin(commits), end(commits)));
	if(!num)
	{
		chan << FG::RED;

		if(doc.has("ref"))
			chan << " " << doc["ref"];

		chan << " deleted" << OFF << chan.flush;
		return;
	}

	if(doc.has("ref"))
		chan << " " << doc["ref"];

	chan << " " << num << " commits";

	if(doc["forced"] == "true")
		chan << " (rebase)";

	if(num > 15)
		chan << BOLD << FG::GRAY << " (please be patient)" << OFF;

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

		const auto lines(tokens(commit["message"], "\n"));
		const auto cm(lines.at(0));
		chan << " " << UNDER2 << cm << OFF;
		if(lines.size() > 1)
			chan << " " << BOLD << FG::GRAY << "(" << (lines.size()-1) << " lines)" << OFF;

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
				return;
			}

			if(doc["state"] == "success")
			{
				if(doc["context"] == "continuous-integration/travis-ci/pr" ||
				   doc["context"] == "continuous-integration/travis-ci/push")
				{
					chan.Stream::clear();
					return;
				}

				chan << FG::GREEN;
			}

			if(doc["state"] == "error")
				chan << FG::RED;

			if(doc["state"] == "failure")
				chan << FG::LRED;

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


void client::handle_github_delete()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	const auto &doc(msg->doc);

	chan << " " << "refs/heads/" << doc["ref"] << chan.flush;
}


void client::handle_github_pull_request()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " " << doc["action"];
	chan << " (" << doc["pull_request.html_url"] << ")";
	chan << " " << UNDER2 << doc["pull_request.title"] << OFF;

	//chan << chan.flush;
	//chan << "| ";
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


void client::handle_github_commit_comment()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " " << doc["action"];
	if(doc.has("comment.path"))
	{
		chan << " in " << doc["comment.path"];
		chan << " +" << doc["comment.line"];
		chan << "@" << doc["comment.position"];
	}
	chan << " (" << doc["comment.html_url"] << ")";
	chan << chan.flush;

	switch(hash(doc["action"]))
	{
		case hash("created"):
		{
			const auto lines(tokens(doc["comment.body"], "\n"));
			size_t i(0);
			for(; i < lines.size() && i < 3; ++i)
				chan << "| " << lines.at(i);

			if(lines.size() > i)
				chan << "| " << BOLD << FG::GRAY << "(" << (lines.size()-i) << " more lines)" << OFF;

			break;
		}
	}

	chan << chan.flush;
}


void client::handle_github_issues()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " " << doc["action"];
	switch(hash(doc["action"]))
	{
		case hash("assigned"):
		case hash("unassigned"):
			chan << " " << doc["assignee.login"];
			break;
	}

	chan << " (" << doc["issue.html_url"] << ")";
	chan << " " << UNDER2 << doc["issue.title"] << OFF;
	chan << chan.flush;

	switch(hash(doc["action"]))
	{
		case hash("opened"):
		{
			const auto lines(tokens(doc["issue.body"], "\n"));
			size_t i(0);
			for(; i < lines.size() && i < 3; ++i)
				chan << "| " << lines.at(i);

			if(lines.size() > i)
				chan << "| " << BOLD << FG::GRAY << "(" << (lines.size()-i) << " more lines)" << OFF;

			break;
		}
	}

	chan << chan.flush;
}


void client::handle_github_issue_comment()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " (" << doc["issue.html_url"] << ")";
	chan << " " << UNDER2 << doc["issue.title"] << OFF;
	chan << chan.flush;

	switch(hash(doc["action"]))
	{
		case hash("created"):
		{
			const auto lines(tokens(doc["comment.body"], "\r\n"));
			size_t i(0);
			for(; i < lines.size() && i < 2; ++i)
				chan << "| " << lines.at(i) << chan.flush;

			if(lines.size() > i)
				chan << "| " << BOLD << FG::GRAY << "(" << (lines.size()-i) << " more lines)" << OFF;

			break;
		}

		case hash("edited"):
		{
			const auto lines(tokens(doc["comment.body"], "\r\n"));
			chan << BOLD << FG::GRAY << "| (edited " << lines.size() << " line comment)" << OFF;
			break;
		}
	}

	chan << chan.flush;
}


void client::handle_github_create()
{
	using namespace colors;

	auto &chan(bot->chans.get(channame));
	auto &doc(msg->doc);

	chan << " " << doc["ref_type"] << OFF;

	switch(hash(doc["ref_type"]))
	{
		case hash("branch"):
		{
			chan << " " << BOLD << doc["ref"] << OFF;
			chan << " from " << BOLD << doc["master_branch"] << OFF;
			chan << chan.flush;

			if(doc.has("description"))
			{
				chan << "| " << doc["description"];
				chan << chan.flush;
			}

			break;
		}
	}
}


void client::respond(const std::string &status)
{
	std::stringstream out;
	out << "HTTP/1.1 " << status << "\r\n";
	out << "Content-Type: application/json\r\n";
	out << "Content-Length: 0\r\n";
	out << "\r\n";
	out << "\r\n";

	send(out.str());
}


void client::send(const std::string &data)
try
{
	const boost::asio::const_buffers_1 bufs(data.data(), data.size());
	if(socket.is_open())
	{
		const auto sent(socket.send(bufs));
		std::cout << socket.remote_endpoint() << " << [" << data << "]" << std::endl;
	}
	else if(sslstream.lowest_layer().is_open())
	{
		const auto sent(sslstream.write_some(bufs));
		std::cout << sslstream.lowest_layer().remote_endpoint() << " << [" << data << "]" << std::endl;
	}
}
catch(const std::exception &e)
{
	std::cerr << "SEND FAILED: " << e.what() << std::endl;
}


void client::error_to_chan(const std::exception &e)
{
	if(!bot->chans.has(channame))
		return;

	//auto &chan(bot->chans.get(channame));
	auto &chan(std::cerr);

	if(socket.is_open())
		chan << "client[" << socket.remote_endpoint() << "] ";

	chan << "error: " << e.what() << std::endl;
}


void set_accept();
void handle_accept(const error_code &ec,
                   std::shared_ptr<client> c)
noexcept try
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
catch(...)
{
	std::cerr << "handle_accept: unknown!" << std::endl;
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
	using namespace fmt::PRIVMSG;

	const auto &text(msg[TEXT]);
	auto toks(tokens(text));
	if(toks.empty() || toks.at(0) != bot->sess.get_nick() + ':')
		return;

	if(user.get_nick() != "jzk")
		return;

	toks.erase(begin(toks));
	if(toks.empty())
	{
		chan << user << "Please make a request." << chan.flush;
		return;
	}

	const auto request(detok(begin(toks), end(toks)));

	std::stringstream out;
	out << request << " HTTP/1.1\r\n";
	out << "Host: api.github.com\r\n";

	const auto &opts(bot->opts);
	if(opts.has("yestifico-auth"))
		out << "Authorization: Basic " << opts["yestifico-auth"] << "\r\n";

	out << "User-Agent: yestifico/0.0.0\r\n";
	out << "Accept: */*\r\n";
	out << "\r\n";

	auto client(std::make_shared<client>());
	(*client)("api.github.com", out.str());
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
catch(...)
{
	std::cerr << "handle_privmsg: unknown!" << std::endl;
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

	sslctx.reset(new boost::asio::ssl::context(*ios, boost::asio::ssl::context::sslv23));
	sslctx->set_default_verify_paths();

	const ip::tcp::endpoint ep(ip::tcp::v4(), bind_port);
	acceptor.reset(new ip::tcp::acceptor(*ios, ep, true));
	set_accept();

	channame = opts.has("yestifico-chan")? opts["yestifico-chan"] : "#charybdis";

	std::cout << "yestifico listening: " << ep << std::endl;
}


extern "C"
void module_fini(Bot *const bot)
noexcept
{
	error_code ec;
	std::unique_lock<std::mutex> lock(*bot);
	if(acceptor)
		acceptor->close(ec);

	for(auto *const &client : clients)
	{
		//client->resolver.cancel();
		client->socket.close(ec);
		client->sslstream.lowest_layer().close(ec);
		client->sslstream.shutdown(ec);
	}

	cond.wait(lock, []
	{
		std::cout << "waiting on " << clients.size() << " clients..." << std::endl;
		return clients.empty();
	});

	bot->events.chan_user.clear(handler::Prio::USER);

	std::cout << "yestifico finished" << std::endl;
}


bool errored(const error_code &ec)
{
	switch(ec.value())
	{
		using namespace boost::system::errc;

		case success:
			return false;

		case operation_canceled:
			cond.notify_all();
			std::atomic_thread_fence(std::memory_order_release);
			return true;

		default:
			throw std::runtime_error(ec.message());
	}
}


std::string getline_crlf(std::istream &in)
{
	std::string ret;
	std::getline(in, ret);
	if(!ret.empty() && ret.back() == '\r')
		ret.pop_back();

	return ret;
}

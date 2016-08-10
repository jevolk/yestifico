/** 
 *  COPYRIGHT 2014 (C) Jason Volk
 *  COPYRIGHT 2014 (C) Svetlana Tkachenko
 *
 *  DISTRIBUTED UNDER THE GNU GENERAL PUBLIC LICENSE (GPL) (see: LICENSE)
 */

#include "ircbot/bot.h"

namespace ph = std::placeholders;
using namespace irc::bot;


Bot *bot;


struct webclient
:std::enable_shared_from_this<webclient>
{
	boost::asio::ip::tcp::socket socket;
	boost::asio::streambuf buf;

	void respond();
	void handle(const boost::system::error_code &ec, size_t avail, std::shared_ptr<webclient>) noexcept;
	void set_handler();

	webclient(boost::asio::io_service &ios)
	:socket{ios}
	,buf{1048576 * 5}
	{
		buf.prepare(buf.max_size());
	}
};


void webclient::set_handler()
{
	static const auto terminator("\r\n\r\n");
	const auto callback(std::bind(&webclient::handle, this, ph::_1, ph::_2, shared_from_this()));
	async_read_until(socket, buf, terminator, callback);
}


void webclient::handle(const boost::system::error_code &ec,
                       size_t avail,
                       std::shared_ptr<webclient>)
noexcept try
{
	switch(ec.value())
	{
		using namespace boost::system::errc;

		case success:                   break;
		case boost::asio::error::eof:   return;
		case operation_canceled:        return;
		default:                        throw boost::system::error_code(ec);
	}

	const scope reset([&]
	{
		buf.consume(avail);
		respond();
		set_handler();
	});

	std::istream in{&buf};
	std::istreambuf_iterator<char> inbeg{in}, inend;

	std::string cmdline;
	std::string event;
	size_t content_length(0);
	tokens(std::string(inbeg, inend), "\r\n", [&]
	(const std::string &text)
	{
		const auto kv(split(text, ": "));
		if(kv.second.empty() || kv.first.at(0) == '{')
		{
			if(cmdline.empty())
			{
				cmdline = text;
				return;
			}

			if(!content_length)
				throw std::runtime_error("content-length missing");

			if(text.size() != content_length)
				throw std::runtime_error("content-length mismatch");
		}
		else switch(hash(tolower(kv.first)))
		{
			case hash("content-length"):
				content_length = lex_cast<size_t>(kv.second);
				return;

			case hash("x-github-event"):
				event = kv.second;
				return;

			default:
				return;
		}

		auto &chan(bot->chans.get("#charybdis"));
		const Adoc doc(text);
		const scope reset([&chan]
		{
			chan << chan.flush;
		});

		using namespace colors;

		if(doc.has("repository.full_name"))
			chan << BOLD << doc["repository.full_name"] << OFF;

		if(doc.has_child("pusher"))
			chan << " by " << doc["pusher.name"];
		else if(doc.has_child("sender"))
			chan << " by " << doc["sender.login"];

		if(!event.empty())
			chan << " " << event;

		if(event == "status" && doc.has("description"))
			chan << " " << FG::GRAY << doc["description"] << OFF;

		if(event == "push" && doc["forced"] == "true")
			chan << " (rebase)";

		if(doc.has("head_commit.id"))
			chan << " @ " << BOLD << FG::CYAN << doc["head_commit.id"] << OFF;

		if(doc.has_child("commits"))
		{
			chan << chan.flush;

			const auto commits(doc.get_child("commits", Adoc{}));
			for(const auto &p : commits)
			{
				const Adoc &commit(p.second.get_child("", Adoc{}));
				chan << "*";
				chan << " " << commit["author.name"];
				if(commit["committer.email"] != commit["author.email"])
					chan << " via " << commit["committer.name"];

				chan << " (" << commit["url"] << ")";
				const auto cm(split(commit["message"], "\n").first);
				chan << " " << BOLD << UNDER2 << cm << OFF;
				chan << chan.flush;
			}
		}
	});
}
catch(const std::exception &e)
{
	auto &chan(bot->chans.get("#charybdis"));
	chan << "error: " << e.what() << chan.flush;
}


void webclient::respond()
{
	static const std::string response
	{
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
		"\r\n"
	};

	socket.send(boost::asio::const_buffers_1(response.data(), response.size()));
}


std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;

void set_accept();
void handle_accept(const boost::system::error_code &ec,
                   std::shared_ptr<webclient> c)
{
	switch(ec.value())
	{
		using namespace boost::system::errc;

		case success:
			break;

		case operation_canceled:
			return;

		default:
			throw std::runtime_error(ec.message());
	}

	c->set_handler();
	set_accept();
}


void set_accept()
{
	auto &ios(bot->sess.get_ios());
	auto client(std::make_shared<webclient>(ios));
	acceptor->async_accept(client->socket, std::bind(&handle_accept, ph::_1, client));
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
	{
		const std::lock_guard<Bot> lock(*bot);
		bot->set_tls_context();
		bot->events.chan_user.add("PRIVMSG",
		                          std::bind(&handle_privmsg, ph::_1, ph::_2, ph::_3),
		                          handler::RECURRING);
	}

	auto &ios(bot->sess.get_ios());
	boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), 6699);
	acceptor.reset(new boost::asio::ip::tcp::acceptor(ios, ep, true));
	set_accept();

	std::cout << "yestifico listening: " << ep << std::endl;
}


extern "C"
void module_fini(Bot *const bot)
noexcept
{
	{
		const std::lock_guard<Bot> lock(*bot);
		bot->events.chan_user.clear(handler::Prio::USER);
	}

	std::cout << "yestifico closing..." << std::endl;
}

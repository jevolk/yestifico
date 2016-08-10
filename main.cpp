/**
 *  COPYRIGHT 2014 (C) Jason Volk
 *  COPYRIGHT 2014 (C) Svetlana Tkachenko
 *
 *  DISTRIBUTED UNDER THE GNU GENERAL PUBLIC LICENSE (GPL) (see: LICENSE)
 */

#include <dlfcn.h>
#include <signal.h>
#include "ircbot/bot.h"
using namespace irc::bot;


std::unique_ptr<Bot> bot;
bool interrupted;

inline
void wait_reload()
{
	sigset_t ours, theirs;
	sigemptyset(&ours);
	sigaddset(&ours, SIGINT);
	sigaddset(&ours, SIGTERM);
	sigaddset(&ours, SIGQUIT);

	int sig;
	sigprocmask(SIG_BLOCK, &ours, &theirs);
	sigwait(&ours, &sig);
	sigprocmask(SIG_SETMASK, &theirs, NULL);
	switch(sig)
	{
		case SIGTERM:
		case SIGQUIT:
			interrupted = true;
			break;

		default:
			break;
	}
}


int main(int argc, char **argv) try
{
	srand(getpid());


	// Setup defaults
	Opts opts;
	opts["connect"] = "true";
	opts["user"] = "yestifico";
	opts["gecos"] = "libircbot";
	opts["quit-msg"] = "Alea iacta est";

	// Parse command line
	opts.parse({argv+1,argv+argc});

	if(opts["nick"].empty())
	{
		fprintf(stderr,"usage: %s [ --var=val | --join=chan ] [...]\n",argv[0]);
		fprintf(stderr,"\ndefaults:\n");
		for(const auto &kv : opts)
			fprintf(stderr,"\t--%s=\"%s\"\n",kv.first.c_str(),kv.second.c_str());

		return -1;
	}

	printf("Current configuration:\n");
	std::cout << opts << std::endl;

	bot.reset(new Bot(opts));             // Create instance of the bot
	(*bot)(Bot::BACKGROUND);

	while(!interrupted) try
	{
		static const auto opener([]
		{
			const auto module(dlopen("./yestifico.so",RTLD_NOW|RTLD_LOCAL));

			if(!module)
				throw Assertive("dlopen() error: ") << dlerror();

			return module;
		});

		const std::unique_ptr<void, void (*)(void *)> module(opener(),[]
		(void *const module)
		{
			if(dlclose(module) != 0)
				throw Assertive("dlclose() error: ") << dlerror();
		});

		using mod_call_t = void (*)(Bot *);
		const auto module_init(reinterpret_cast<mod_call_t>(dlsym(module.get(),"module_init")));
		{
			const auto err(dlerror());
			if(!module_init || err)
				throw Assertive("dlsym() error: ") << err;
		}

		const auto module_fini(reinterpret_cast<mod_call_t>(dlsym(module.get(),"module_fini")));
		{
			const auto err(dlerror());
			if(!module_fini || err)
				throw Assertive("dlsym() error: ") << err;
		}

		module_init(bot.get());
		wait_reload();
		module_fini(bot.get());
	}
	catch(const Assertive &e)
	{
		std::cerr << "Module error: " << e.what() << std::endl;
		std::cerr << "Waiting to try again..." << std::endl;
		wait_reload();
	}

	bot->quit();
	recvq::ios.poll();
}
catch(const std::exception &e)
{
	std::cerr << "Exception: " << e.what() << std::endl;
	return -1;
}

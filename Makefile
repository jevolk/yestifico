###############################################################################
#
# YESTIFICO Makefile
#
#	Author:
#		COPYRIGHT (C) Jason Volk 2016
#
# This file is free and available under the GNU GPL terms specified in COPYING.
#
# The production build process should work by simply typing `make`. libircbot
# is built recursively and may require a second `make` command to complete
# linking.
#
# For developers, export YESTIFICO_DEVELOPER=1 which adjusts the CCFLAGS for non-
# production debug builds.
#
###############################################################################


###############################################################################
#
# YESTIFICO options
#

YESTIFICO_CC       := g++
YESTIFICO_VERSTR   := $(shell git describe --tags)
YESTIFICO_CCFLAGS  := -std=c++14 -Iircbot/stldb -DYESTIFICO_VERSION=\"$(YESTIFICO_VERSTR)\" -fstack-protector
YESTIFICO_LDFLAGS  += -fuse-ld=gold -Wl,--no-gnu-unique -Lircbot/
YESTIFICO_WFLAGS   += -pedantic                             \
                      -Wall                                 \
                      -Wextra                               \
                      -Wcomment                             \
                      -Waddress                             \
                      -Winit-self                           \
                      -Wuninitialized                       \
                      -Wunreachable-code                    \
                      -Wvolatile-register-var               \
                      -Wvariadic-macros                     \
                      -Woverloaded-virtual                  \
                      -Wpointer-arith                       \
                      -Wlogical-op                          \
                      -Wcast-align                          \
                      -Wcast-qual                           \
                      -Wstrict-aliasing=2                   \
                      -Wstrict-overflow                     \
                      -Wwrite-strings                       \
                      -Wformat-y2k                          \
                      -Wformat-security                     \
                      -Wformat-nonliteral                   \
                      -Wfloat-equal                         \
                      -Wdisabled-optimization               \
                      -Wno-missing-field-initializers       \
                      -Wmissing-format-attribute            \
                      -Wno-unused-parameter                 \
                      -Wno-unused-label                     \
                      -Wno-unused-variable                  \
                      -Wsuggest-attribute=format



###############################################################################
#
# Composition of YESTIFICO options and user environment options
#


ifdef YESTIFICO_DEVELOPER
	YESTIFICO_CCFLAGS += -ggdb -O0
	export IRCBOT_DEVELOPER := 1
else
	YESTIFICO_CCFLAGS += -DNDEBUG -D_FORTIFY_SOURCE=1 -O3
endif


YESTIFICO_CCFLAGS += $(YESTIFICO_WFLAGS) $(CCFLAGS)
YESTIFICO_LDFLAGS += $(LDFLAGS)



###############################################################################
#
# Final build targets composition
#

YESTIFICO_LIBRARIES := libircbot
YESTIFICO_TARGETS := yestifico.so yestifico


all:  $(YESTIFICO_LIBRARIES) $(YESTIFICO_TARGETS)

clean:
	$(MAKE) -C ircbot clean
	rm -f *.o *.so $(YESTIFICO_TARGETS)

libircbot:
	$(MAKE) -C ircbot


yestifico: main.o
	$(YESTIFICO_CC) -o $@ $(YESTIFICO_CCFLAGS) -rdynamic $(YESTIFICO_LDFLAGS) $^ -lircbot -lleveldb -lboost_system -lpthread -ldl

yestifico.so: yestifico.o
	$(YESTIFICO_CC) -o $@ $(YESTIFICO_CCFLAGS) -shared $(YESTIFICO_LDFLAGS) $^ -lcrypto -lssl

yestifico.o: yestifico.cpp
	$(YESTIFICO_CC) -c -o $@ $(YESTIFICO_CCFLAGS) -fPIC $<

main.o: main.cpp
	$(YESTIFICO_CC) -c -o $@ $(YESTIFICO_CCFLAGS) $<

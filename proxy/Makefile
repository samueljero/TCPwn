###############################################################################
# Author: Samuel Jero <sjero@purdue.edu>
###############################################################################
CPP=g++
CC=gcc
CPPFLAGS=-O2 -Wall -Werror -g

BINARIES=proxy sndcmd
PROXY_HEADERS=proxy.h control.h csv.h args.h iface.h checksums.h
PROXY_SRC=proxy.cc control.cc args.cc csv.cc attacker.cc iface.cc checksums.c
SNDCMD_SRC=sndcmd.cc


.PHONY: clean

all: $(BINARIES)

clean:
	rm -f $(BINARIES) *.o *~
        
proxy: $(PROXY_HEADERS) $(PROXY_SRC)
	$(CPP) $(CPPFLAGS) $(PROXY_SRC) -o proxy -lpthread -Wl,-rpath,`pwd` -L`pwd`

sndcmd: $(SNDCMD_SRC)
	$(CPP) $(CPPFLAGS) $(SNDCMD_SRC) -lpthread -o sndcmd


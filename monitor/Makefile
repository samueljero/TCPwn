###############################################################################
# Author: Samuel Jero <sjero@purdue.edu>
###############################################################################
CPP=g++
CC=gcc
CPPFLAGS=-O2 -Wall -Werror -Wextra -Wpedantic -g

BINARIES=monitor sndcmd
MONITOR_HEADERS=monitor.h control.h csv.h args.h iface.h proto.h tcp.h
MONITOR_SRC=monitor.cc control.cc args.cc csv.cc tracker.cc iface.cc tcp.cc
SNDCMD_SRC=sndcmd.cc


.PHONY: clean

all: $(BINARIES)

clean:
	rm -f $(BINARIES) *.o *~
        
monitor: $(MONITOR_HEADERS) $(MONITOR_SRC)
	$(CPP) $(CPPFLAGS) $(MONITOR_SRC) -o monitor -lpthread -Wl,-rpath,`pwd` -L`pwd` -lrt

sndcmd: $(SNDCMD_SRC)
	$(CPP) $(CPPFLAGS) $(SNDCMD_SRC) -lpthread -o sndcmd


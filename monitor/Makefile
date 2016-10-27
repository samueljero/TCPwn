###############################################################################
# Author: Samuel Jero <sjero@purdue.edu>
###############################################################################
CPP=g++
CC=gcc
CPPFLAGS=-fPIC -pie -O2 -Wall -Werror -Wextra -g

BINARIES=monitor
MONITOR_HEADERS=monitor.h iface.h proto.h algorithm.h classic.h tcp.h
MONITOR_SRC=monitor.cc tracker.cc iface.cc classic.cc tcp.cc


.PHONY: clean

all: $(BINARIES)

clean:
	rm -f $(BINARIES) *.o *~
        
monitor: $(MONITOR_HEADERS) $(MONITOR_SRC)
	$(CPP) $(CPPFLAGS) $(MONITOR_SRC) -o monitor -lpthread -lrt


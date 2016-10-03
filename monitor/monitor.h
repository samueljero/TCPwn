/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _MONITOR_H
#define _MONITOR_H
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <pthread.h>


class Message{
	public:
		char *buff;
		int len;
		int alloc;
};

enum direction {
	NONE = 0,
	FORWARD = 1,
    BACKWARD = 2
};

class Iface;

class pkt_info {
	public:
		bool valid;
		Message msg;
		enum direction dir;
		int ip_type;
		char *ip_src;
		char *ip_dst;
		char *mac_src;
		char *mac_dst;
		Iface *rcv;
		Iface *snd;
};

/* Get interface commands */
Iface *GetForwardInterface();
Iface *GetBackwardInterface();

/*debug printf
 * Levels:
 * 	0) Always print even if debug isn't specified
 *  1) Errors and warnings... Don't overload the screen with too much output
 *  2) Notes and per-packet processing info... as verbose as needed
 */
extern int monitor_debug;
void dbgprintf(int level, const char *fmt, ...);

#endif

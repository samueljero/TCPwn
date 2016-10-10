/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* Congestion Control Sender Monitor: Main
******************************************************************************/
#include <list>
#include <vector>
#include <string>
#include <stdarg.h>
#include "monitor.h"
#include "iface.h"
#include "tracker.h"
using namespace std;


#define MONITOR_VERSION 0.1
#define COPYRIGHT_YEAR 2016

int monitor_debug = 1;

Iface* iface1;
Iface* iface2;

void version();
void usage();
void control_loop(int port);
static void sig_alrm_handler(int signo);


int main(int argc, char** argv)
{
	int ctlport = 4444;
	vector<string> ifaces;
	struct sockaddr_in outputaddr;
	sigset_t sigset;
    struct sigaction sa;
	memset(&outputaddr, 0, sizeof(struct sockaddr_in));

	/*parse commandline options*/
	if (argc == 1) {
		usage();
	}

	/*loop through commandline options*/
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-V") == 0) { /* -V */
			version();
		} else if (strcmp(argv[i], "-h") == 0) { /*-h*/
			usage();
		} else if (strcmp(argv[i], "-v") == 0) { /*-v*/
			monitor_debug++;
		} else if (strcmp(argv[i], "-p") == 0) { /*-p*/
			i++;
			ctlport = atoi(argv[i]);
			if ( ctlport <= 0 || ctlport > 65535) {
				dbgprintf(0, "Error parsing control port: %s\n", argv[i]);
				usage();
			}
		} else if (strcmp(argv[i], "-o") == 0) { /*-o*/
			i++;
			/* Parse Line */
			int port = 0;
			char *ip = NULL;
			sscanf(argv[i], "%m[^:]:%i",&ip, &port);
			if (!port || !ip){
				dbgprintf(0,"Error parsing output connection description: %s\n", argv[i]);
				usage();
			}

			/* Parse IP */
			struct addrinfo hints;
			struct addrinfo *results, *p;
			int found;
			int ret;
			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_family = AF_INET;
			if ((ret = getaddrinfo(ip, NULL, &hints, &results)) < 0) {
				dbgprintf(0, "Error parsing output connection description: %s\n", gai_strerror(ret));
				usage();
			}
			found = 0;
			for (p = results; p!=NULL; p = p->ai_next) {
				memcpy(&outputaddr, p->ai_addr, sizeof(struct sockaddr_in));
				found = 1;
				break;
			}
			if (found == 0) {
				dbgprintf(0, "Error parsing output connection  description: No IP addresses found\n");
				usage();
			}
			outputaddr.sin_port = htons(port);
		} else if (strcmp(argv[i], "-i") == 0) { /*-i*/
			i++;
			ifaces.push_back(string(&argv[i][0]));
		}else{
			usage();
		}
	}

    /* Ignore SIGALRM */
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);           
    sigprocmask(SIG_BLOCK, &sigset, NULL);
	/* Setup Default handler*/
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_alrm_handler;
    sigaction(SIGALRM, &sa, NULL);

	/* Initialize Tracker */
	Tracker::get().start();
	Tracker::get().openOutputSocket(outputaddr);

	/* Setup Ifaces */
	if (ifaces.size() != 2) {
		dbgprintf(0, "Error: There must be exactly two interfaces specified\n");
		usage();
	}
	iface1 = new Iface(ifaces[0]);
	iface2 = new Iface(ifaces[1]);
	iface1->setOther(iface2);
	iface2->setOther(iface1);
	iface1->setDirection(FORWARD);
	iface2->setDirection(BACKWARD);
	if (!iface1->start() || !iface2->start()) {
		dbgprintf(0, "Error: Failed to attach to interfaces (%s,%s)\n",ifaces[0].c_str(), ifaces[1].c_str());
		return -1;
	}

	/* Start listening for control connections */
	control_loop(ctlport);

	/* Cleanup */
	iface1->stop();
	iface2->stop();
	Tracker::get().stop();
	return 0;
}

int setup_ifaces(vector<string> ifaces)
{
	dbgprintf(1, "Iface 1: %s\n", ifaces[0].c_str());
	return 0;
}

Iface *GetForwardInterface() {
	return iface1;
}

Iface *GetBackwardInterface() {
	return iface2;
}

void control_loop(int port)
{
	struct sockaddr_in sin;
	int sock;
	int new_sock;

	/* Setup Socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		dbgprintf(0, "Error: Can't create control_socket: %s\n",strerror(errno));
		return;
	}

	int so_reuseaddr = 1;
	if (setsockopt(sock, SOL_SOCKET,SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr))< 0){
		dbgprintf(0, "Error: Can't create listen_socket: %s\n",strerror(errno));
		return;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0 ) {
		dbgprintf(0, "Error: Can't bind control_socket to port %i: %s\n",port, strerror(errno));
		return;
	}

	if (listen(sock, 5) < 0) {
		dbgprintf(0, "Error: Can't listen on control_socket: %s\n",strerror(errno));
		return;
	}

	while(true){
		new_sock = accept(sock, NULL, NULL);
		if (new_sock < 0) {
			dbgprintf(0, "Error: Accept() failed!: %s\n", strerror(errno));
			break;
		}

		dbgprintf(3, "New Control Connection\n");
		close(new_sock);
	}
}

void version()
{
	dbgprintf(0, "monitor version %.1f\n",MONITOR_VERSION);
	dbgprintf(0, "Copyright (C) %i Samuel Jero <sjero@purdue.edu>\n",COPYRIGHT_YEAR);
	//dbgprintf(0, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	//dbgprintf(0, "This is free software, and you are welcome to\n");
	//dbgprintf(0, "redistribute it under certain conditions.\n");
	exit(0);
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0,"Usage: monitor [-v] [-V] [-h][-i interface] [-p control_port][-o host:port]\n");
	dbgprintf(0, "          -v   verbose. May be repeated for additional verbosity.\n");
	dbgprintf(0, "          -V   Version information\n");
	dbgprintf(0, "          -i   Interface to listen and bridge on. Must specify exactly two -i options\n");
	dbgprintf(0, "          -p   TCP port to listen on to indicate that monitor is operational\n");
	dbgprintf(0, "          -o   Option a TCP connection to this location and output sender's current state during connection\n");
	dbgprintf(0, "          -h   Help\n");
	exit(0);
}

/*Debug Printf*/
void dbgprintf(int level, const char *fmt, ...)
{
    va_list args;
    if (monitor_debug >= level) {
    	va_start(args, fmt);
    	vfprintf(stderr, fmt, args);
    	va_end(args);
    }
}

/* Dummy signal handler */
static void sig_alrm_handler(int signo) 
{
if (signo == SIGALRM) {}
}

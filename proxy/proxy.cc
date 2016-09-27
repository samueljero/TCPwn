/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* TCP Congestion Control Proxy: Main
******************************************************************************/
#include <list>
#include <vector>
#include <string>
#include <stdarg.h>
#include "proxy.h"
#include "control.h"
#include "iface.h"
#include "attacker.h"
using namespace std;


#define PROXY_VERSION 0.1
#define COPYRIGHT_YEAR 2016

int proxy_debug = 1;

list<Control*> controls;
Iface* iface1;
Iface* iface2;

void version();
void usage();
void control_loop(int port);
void cleanupControls();


int main(int argc, char** argv)
{
	int ctlport = 3333;
	vector<string> ifaces;

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
			proxy_debug++;
		} else if (strcmp(argv[i], "-p") == 0) { /*-p*/
			i++;
			ctlport = atoi(argv[i]);
			if ( ctlport <= 0 || ctlport > 65535) {
				dbgprintf(0, "Error parsing control port: %s\n", argv[i]);
				usage();
			}
		} else if (argv[i][0] == '-' && argv[i][1] == 'i'){ /*-c*/
			i++;
			ifaces.push_back(string(&argv[i][0]));
		}else{
			usage();
		}
	}

	/* Initialize Attacker */
	Attacker::get().start();

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
	Attacker::get().stop();
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
	Control *ctl;

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
		
		ctl = new Control(new_sock);
		ctl->start();
		controls.push_front(ctl);

		cleanupControls();
	}
}

void cleanupControls()
{
	for (list<Control*>::iterator it = controls.begin(); it != controls.end(); it++) {
		if( !(*it)->isRunning()) {
			delete *it;
			controls.erase(it);
			it = controls.begin();
		}
	}
}

void version()
{
	dbgprintf(0, "proxy version %.1f\n",PROXY_VERSION);
	dbgprintf(0, "Copyright (C) %i Samuel Jero <sjero@purdue.edu>\n",COPYRIGHT_YEAR);
	//dbgprintf(0, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	//dbgprintf(0, "This is free software, and you are welcome to\n");
	//dbgprintf(0, "redistribute it under certain conditions.\n");
	exit(0);
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0,"Usage: proxy [-v] [-V] [-h] [-i interface] [-p control_port]\n");
	dbgprintf(0, "          -v   verbose. May be repeated for additional verbosity.\n");
	dbgprintf(0, "          -V   Version information\n");
	dbgprintf(0, "          -h   Help\n");
	exit(0);
}

/*Debug Printf*/
void dbgprintf(int level, const char *fmt, ...)
{
    va_list args;
    if (proxy_debug >= level) {
    	va_start(args, fmt);
    	vfprintf(stderr, fmt, args);
    	va_end(args);
    }
}

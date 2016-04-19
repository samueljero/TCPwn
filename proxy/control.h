/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* TCP Congestion Control Proxy: Control Connection Support
******************************************************************************/
#ifndef _CONTROL_H
#define _CONTROL_H
#include "proxy.h"
using namespace std;

class Control {
	public:
		Control(int sock);
		~Control(){}
		bool start();
		bool isRunning() {return running;}

	private:
		static void* thread_run(void* arg);
		void run();
		Message recvMsg();
		bool sendMsg(Message m);

		int sock;
		bool running;
		pthread_t ctl_thread;
};

#endif

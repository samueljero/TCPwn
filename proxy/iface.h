/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* TCP Congestion Control Proxy: Interface read/write thread
******************************************************************************/
#ifndef _IFACE_H
#define _IFACE_H
#include "proxy.h"
#include <string>

class Iface{
	public:
		Iface();
		Iface(std::string interface);
		~Iface();
		bool sendm(Message m);
		bool start();
		bool stop();
		bool isRunning() {return running || rcv_thread_running;}
		void setDirection(enum direction dir) {this->dir = dir;}
		enum direction getDirection() {return dir;}
		void setOther(Iface *othr) { this->other = othr;}
		Iface*	getOther() {return other;}

	private:
		static void* rcv_thread_run(void* arg);
		void rcv_run();
		bool _stop();
		Message recvMsg();

		int sock;
		std::string iface;
		Iface* other;
		bool running;
		bool rcv_thread_running;
		bool rcv_thread_cleanup;
		bool print_messages;
		enum direction dir;
		pthread_t rcv_thread;
};

#endif

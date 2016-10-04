/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _TCP_H
#define _TCP_H

#include "proto.h"
#include <netinet/tcp.h>


class TCP: public Proto {
	public:
		TCP();
		~TCP();
		virtual void new_packet(pkt_info pk, Message hdr);
		virtual bool start();
		virtual bool stop();
		virtual bool isRunning() {return running || thread_running;}
		virtual bool hasIPProto(int num) {return num == 6;}

	private:
		static void* thread_run(void* arg);
		void run();
		void updateClassicCongestionControl(pkt_info pk, Message hdr);
		void processClassicCongestionControl();

		pthread_rwlock_t lock;
		pthread_t thread;
		bool running;
		bool thread_running;
		bool thread_cleanup;

		unsigned int tcp_port1;
		unsigned int tcp_port2;
		unsigned int tcp_data_pkts;
		unsigned int tcp_ack_pkts;
		unsigned int tcp_data_low;
		unsigned int tcp_data_high;
		unsigned int tcp_ack_low;
		unsigned int tcp_ack_high;
		int state;
		int old_state;
		int idle_periods;
};

#endif

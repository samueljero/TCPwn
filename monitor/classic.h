/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
* Congestion Control Sender Monitor: Classic AIMD, loss-based CC algorithm
******************************************************************************/
#ifndef _CLASSIC_H
#define _CLASSIC_H

#include "algorithm.h"
#include "proto.h"


#define STATE_UNKNOWN 0
#define STATE_INIT 1
#define STATE_SLOW_START 2
#define STATE_CONG_AVOID 3
#define STATE_FAST_RECOV 4
#define STATE_RTO 5
#define STATE_END 6

#define INT_TME 10
#define INT_PKT 5
#define MSEC2USEC 1000
#define MSEC2NSEC 1000000

class Classic: public Algorithm {
	public:
		Classic(Proto *p);
		~Classic();
		virtual void new_packet(pkt_info pk, Message hdr);
		virtual bool start();
		virtual bool stop();
		virtual bool isRunning() {return running || thread_running;}

	private:
		static void* thread_run(void* arg);
		void run();
		void processClassicCongestionControl();
		void printState(int oldstate, int state);
		char* timestamp(char* buff, int len);
		void triggerTimerNow();

		pthread_t thread;
		bool running;
		bool thread_running;
		bool thread_cleanup;
		Proto *p;

		int state;
		int old_state;
		int idle_periods;
		bool urgent_event;
		double prior_ratio;
		struct timeval last_packet;
		struct timeval last_idle;
		pthread_mutex_t time_lock;
		timer_t pkt_timr;
		timer_t int_timr;
};

#endif

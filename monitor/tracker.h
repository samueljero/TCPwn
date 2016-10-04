/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* Congestion Control Sender State Tracker: Tracker Header
******************************************************************************/
#ifndef _TRACKER_H
#define _TRACKER_H
#include "monitor.h"
#include "args.h"
#include "proto.h"
#include <map>
#include <list>
#include <vector>
#include <string>
#include <sys/time.h>

#define ACTION_ID_ERR (-1)
#define ACTION_ID_MIN (-1)
#define ACTION_ID_MAX (-1)

#define PROTO_ID_ERR (-1)
#define PROTO_ID_MIN 0
#define PROTO_ID_TCP 0
#define PROTO_ID_MAX 0

class Tracker{
	private:
		Tracker();

	public:
		~Tracker();
		static Tracker& get();
		bool addCommand(Message m, Message *resp);
		pkt_info track(pkt_info pk);
		uint32_t normalize_addr(char* s);
		bool normalize_mac(char* str, char* raw);
		bool start();
		bool stop();
		bool isRunning() {return proto && proto->isRunning();}

	private:
		void parseEthernet(pkt_info pk, Message cur);
		void parseIPv4(pkt_info pk, Message cur);
		int normalize_action_type(char *s);
		int normalize_proto(char *s);
		unsigned long normalize_time(char *s);
		void print(pkt_info pk);

		Proto* proto;
		pthread_rwlock_t lock;
};


#endif

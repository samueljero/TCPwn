/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* Congestion Control Sender State Tracker: Tracker Header
******************************************************************************/
#ifndef _TRACKER_H
#define _TRACKER_H
#include "monitor.h"
#include "proto.h"
#include "algorithm.h"
#include <map>
#include <list>
#include <vector>
#include <string>
#include <sys/time.h>

#define PROTO_ID_ERR (-1)
#define PROTO_ID_MIN 0
#define PROTO_ID_TCP 0
#define PROTO_ID_MAX 0

#define ALG_ID_ERR (-1)
#define ALG_ID_MIN 0
#define ALG_ID_CLASSIC 0
#define ALG_ID_MAX 0

class Tracker{
	private:
		Tracker();

	public:
		~Tracker();
		static Tracker& get();
		pkt_info track(pkt_info pk);
		bool start();
		bool stop();
		bool isRunning() {return alg && alg->isRunning();}
		bool openOutputSocket(struct sockaddr_in &addr);
		bool closeOutputSocket();
		bool setAlgorithmAndProtocol(char *alg, char* proto);
		void sendState(const char *state, const char* ip1, const char* ip2, const char* proto);

	private:
		void parseEthernet(pkt_info pk, Message cur);
		void parseIPv4(pkt_info pk, Message cur);
		int normalize_proto(char *s);
		int normalize_algorithm(char *s);
		int is_int(char *v);
		void print(pkt_info pk);
		bool sendMsg(Message m);
		void readAndThrowAway();

		Proto* proto;
		Algorithm* alg;
		int alg_id;
		int proto_id;
		pthread_mutex_t lock;
		struct sockaddr_in output_addr;
		int sock;
};


#endif

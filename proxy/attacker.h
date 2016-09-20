/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* TCP Congestion Control Proxy: Malicious Processing
******************************************************************************/
#ifndef _ATTACKER_H
#define _ATTACKER_H
#include "proxy.h"
#include "args.h"
#include "proto.h"
#include <map>
#include <list>
#include <vector>
#include <string>
#include <sys/time.h>

#define ACTION_ID_ERR			(-1)
#define ACTION_ID_MIN			0
#define ACTION_ID_ACTIVE		0
#define ACTION_ID_TIME			1
#define ACTION_ID_INJECT		2
#define ACTION_ID_DIV			3
#define ACTION_ID_DUP			4
#define ACTION_ID_PREACK		5
#define ACTION_ID_RENEGE		6
#define ACTION_ID_BURST			7
#define ACTION_ID_PRINT			8
#define ACTION_ID_CLEAR			9
#define ACTION_ID_MAX			9

#define PROTO_ID_ERR (-1)
#define PROTO_ID_MIN 0
#define PROTO_ID_TCP 0
#define PROTO_ID_MAX 0

#define METHOD_ID_ERR (-1)
#define METHOD_ID_MIN 0
#define METHOD_ID_ABS 0
#define METHOD_ID_MAX 0


class Attacker{
	private:
		Attacker();

	public:
		~Attacker();
		static Attacker& get();
		bool addCommand(Message m, Message *resp);
		pkt_info doAttack(pkt_info pk);
		pkt_info fixupAndSend(pkt_info pk, Message ip_payload, bool dosend);
		uint32_t normalize_addr(char* s);
		bool normalize_mac(char* str, char* raw);
		bool start();
		bool stop();

	private:
		pkt_info parseEthernet(pkt_info pk, Message cur);
		Message fixupEthernet(Message cur, Message ip_payload);
		pkt_info parseIPv4(pkt_info pk, Message cur);
		Message fixupIPv4(Message cur, Message ip_payload);
		pkt_info check_connection(pkt_info pk, Message cur);
		int normalize_action_type(char *s);
		int normalize_proto(char *s);
		unsigned long normalize_time(char *s);
		int normalize_method(char *s);
		Proto* find_or_create_proto(uint32_t src, uint32_t dst, int proto);
		Proto* find_proto(uint32_t src, uint32_t dst);
		Proto* create_proto(uint32_t src, uint32_t dst, int proto);
		bool clear_connections();
		void last_packet(Message *res);
		void get_conn_duration(Proto *obj, Message *res);

		void print(pkt_info pk);
	
		//src,dest,object
		std::map<uint32_t,std::map<uint32_t,Proto*> > connections;
		int ipv4_id;
		pthread_rwlock_t lock;

		timeval last_pkt;
		pthread_mutex_t time_lock;
};


#endif

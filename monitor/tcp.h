/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
* Congestion Control Sender Monitor: TCP specific header
******************************************************************************/
#ifndef _TCP_H
#define _TCP_H

#include "proto.h"
#include <netinet/tcp.h>

#define TCP_STATE_UNKNOWN 0
#define TCP_STATE_START 1
#define TCP_STATE_MID 2
#define TCP_STATE_END 3

class TCP: public Proto {
	public:
		TCP();
		~TCP();
		virtual bool new_packet(pkt_info pk, Message hdr);
		virtual bool hasIPProto(int num) {return num == 6;}
		virtual const char* name() {return "TCP";}
		virtual void lockCtrs() {pthread_rwlock_wrlock(&lock);}
		virtual void unlockCtrs() {pthread_rwlock_unlock(&lock);}
		virtual unsigned long DataPkts() {return tcp_data_pkts;}
		virtual unsigned long AckPkts() {return tcp_ack_pkts;}
		virtual unsigned long DataBytes() {return tcp_data_bytes;}
		virtual unsigned long AckBytes() {return tcp_ack_bytes;}
		virtual unsigned long Retransmissions() {return tcp_retransmits;}
		virtual void setAckHolds();
		virtual bool areAckHoldsPassed();
		virtual bool isStart() {return state == TCP_STATE_START;}
		virtual bool isEnd() {return state == TCP_STATE_END;}
		virtual bool isUnknown() {return state == TCP_STATE_UNKNOWN;}
		virtual void resetCtrs();
		virtual const char* getIP1() {return ip1str;}
		virtual const char* getIP2() {return ip2str;}


	private:
		void updateTCPVars(Message hdr);
		void resolveIP2str(uint32_t ip, char* str, int len);

		pthread_rwlock_t lock;

		unsigned int tcp1_port;
		unsigned int tcp1_seq_low;
		unsigned int tcp1_seq_high;
		unsigned int tcp1_ack_low;
		unsigned int tcp1_ack_high;
		unsigned int tcp1_ack_hold;
		unsigned int tcp2_port;
		unsigned int tcp2_seq_low;
		unsigned int tcp2_seq_high;
		unsigned int tcp2_ack_low;
		unsigned int tcp2_ack_high;
		unsigned int tcp2_ack_hold;
		
		unsigned int tcp_data_pkts;
		unsigned int tcp_data_bytes;
		unsigned int tcp_ack_pkts;
		unsigned int tcp_ack_bytes;
		unsigned int tcp_ack_dup;
		unsigned int tcp_retransmits;
		int state;
		int old_state;
		int idle_periods;
		uint32_t ip1;
		uint32_t ip2;
		char ip1str[INET_ADDRSTRLEN];
		char ip2str[INET_ADDRSTRLEN];
};

#endif

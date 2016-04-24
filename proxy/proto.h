/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _PROTO_H
#define _PROTO_H

#include "proxy.h"

class inject_info {
	public:
	char* mac_src;
	char* mac_dst;
	char* ip_src;
	char* ip_dst;
	int tcp_src;
	int tcp_dst;
	int type;
	int window;
	unsigned long seq;
	unsigned long ack;
	int freq;
}

class Proto {
	public:
		virtual pkt_info new_packet(pkt_info pk, Message hdr) = 0;
		virtual bool SetInject(unsigned long start, unsigned long stop, inject_info &info) = 0;
		virtual bool SetDivision(unsigned long start, unsigned long stop, int bytes_per_chunk) = 0;
		virtual bool SetDup(unsigned long start, unsigned long stop, int num) = 0;
		virtual bool SetPreAck(unsigned long start, unsigned long stop, int amt) = 0;
		virtual bool SetRenege(unsigned long start, unsigned long stop, int amt, int growth) = 0;
		virtual bool SetBurst(unsigned long start, unsigned long stop, int num) = 0;
};

#endif

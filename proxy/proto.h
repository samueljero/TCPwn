/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _PROTO_H
#define _PROTO_H

#include "proxy.h"

#define MAC_MAX 20
#define IP_MAX 50

class inject_info {
	public:
	char mac_src[MAC_MAX];
	char mac_dst[MAC_MAX];
	char ip_src[IP_MAX];
	char ip_dst[IP_MAX];
	int port_src;
	int port_dst;
	int type;
	int window;
	unsigned long seq;
	unsigned long ack;
	int freq;
	int method;
	enum direction dir;
	unsigned long start;
	unsigned long stop;
};

class Proto {
	public:
		virtual ~Proto() {}
		virtual pkt_info new_packet(pkt_info pk, Message hdr) = 0;
		virtual bool SetInject(unsigned long start, unsigned long stop, inject_info &info) = 0;
		virtual bool SetDivision(unsigned long start, unsigned long stop, int bytes_per_chunk) = 0;
		virtual bool SetDup(unsigned long start, unsigned long stop, int num) = 0;
		virtual bool SetPreAck(unsigned long start, unsigned long stop, int amt, int method) = 0;
		virtual bool SetRenege(unsigned long start, unsigned long stop, int amt, int growth) = 0;
		virtual bool SetBurst(unsigned long start, unsigned long stop, int num) = 0;
		virtual bool Clear() = 0;
		virtual bool SetPrint(bool on) = 0;
		virtual bool GetDuration(timeval *tm) = 0;
		virtual bool GetBytes(unsigned long *bytes) = 0;
};

#endif

/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * Congestion Control Sender Monitor: General Proto
******************************************************************************/
#ifndef _PROTO_H
#define _PROTO_H

#include "monitor.h"

class Proto {
	public:
		virtual ~Proto() {}
		virtual bool new_packet(pkt_info pk, Message hdr) = 0;
		virtual bool hasIPProto(int num) = 0;
		virtual void lockCtrs() = 0;
		virtual void unlockCtrs() = 0;
		virtual const char* name() = 0;
		virtual unsigned long DataPkts() = 0;
		virtual unsigned long AckPkts() = 0;
		virtual unsigned long DataBytes() = 0;
		virtual unsigned long AckBytes() = 0;
		virtual unsigned long Retransmissions() = 0;
		virtual void setAckHolds() = 0;
		virtual bool areAckHoldsPassed() = 0;
		virtual bool isStart() = 0;
		virtual bool isEnd() = 0;
		virtual bool isUnknown() = 0;
		virtual void resetCtrs() = 0;
		virtual const char* getIP1() = 0;
		virtual const char* getIP2() = 0;
};

#endif

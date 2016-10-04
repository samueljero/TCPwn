/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _PROTO_H
#define _PROTO_H

#include "monitor.h"

class Proto {
	public:
		virtual ~Proto() {}
		virtual void new_packet(pkt_info pk, Message hdr) = 0;
		virtual bool stop() = 0;
		virtual bool start() = 0;
		virtual bool isRunning() = 0;
		virtual bool hasIPProto(int num) = 0;
};

#endif

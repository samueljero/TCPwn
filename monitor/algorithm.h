/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * Congestion Control Sender Monitor: General CC Algorithm
******************************************************************************/
#ifndef _ALGORITHM_H
#define _ALGORITHM_H

#include "monitor.h"

class Algorithm {
	public:
		virtual ~Algorithm () {}
		virtual void new_packet(pkt_info pk, Message hdr) = 0;
		virtual bool stop() = 0;
		virtual bool start() = 0;
		virtual bool isRunning() = 0;
};

#endif

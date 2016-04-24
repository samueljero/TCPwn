/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _TCP_H
#define _TCP_H

#include "proto.h"


class TCP: public Proto {
	public:
		virtual pkt_info new_packet(pkt_info pk, Message hdr);
		virtual bool SetInject(unsigned long start, unsigned long stop, inject_info &info);
		virtual bool SetDivision(unsigned long start, unsigned long stop, int bytes_per_chunk);
		virtual bool SetDup(unsigned long start, unsigned long stop, int num);
		virtual bool SetPreAck(unsigned long start, unsigned long stop, int amt);
		virtual bool SetRenege(unsigned long start, unsigned long stop, int amt, int growth);
		virtual bool SetBurst(unsigned long start, unsigned long stop, int num);
};

#endif

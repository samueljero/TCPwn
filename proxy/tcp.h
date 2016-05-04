/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _TCP_H
#define _TCP_H

#include "proto.h"
#include <netinet/tcp.h>


class tcp_half {
	public:
	uint32_t ip;
	char mac[6];
	uint16_t port;
	
	unsigned long initial_seq;
	unsigned long initial_ack;
	unsigned long high_seq;
	unsigned long high_ack;
	unsigned long window;
	unsigned long pkts;
};


class TCP: public Proto {
	public:
		TCP(uint32_t src, uint32_t dst);
		~TCP();
		virtual pkt_info new_packet(pkt_info pk, Message hdr);
		virtual bool SetInject(unsigned long start, unsigned long stop, inject_info &info);
		virtual bool SetDivision(unsigned long start, unsigned long stop, int bytes_per_chunk);
		virtual bool SetDup(unsigned long start, unsigned long stop, int num);
		virtual bool SetPreAck(unsigned long start, unsigned long stop, int amt);
		virtual bool SetRenege(unsigned long start, unsigned long stop, int amt, int growth);
		virtual bool SetBurst(unsigned long start, unsigned long stop, int num);
		virtual bool Clear();
		virtual bool SetPrint(bool on);

	private:
		pkt_info process_packet(pkt_info pk, Message hdr, tcp_half &src, tcp_half &dst);
		void init_conn_info(pkt_info pk, struct tcphdr *tcph, tcp_half &src, tcp_half &dst);

		tcp_half fwd;
		tcp_half rev;

		bool do_div;
		bool do_dup;
		bool do_preack;
		bool do_renege;
		bool do_burst;
		bool do_print;

		unsigned long div_start;
		unsigned long div_stop;
		unsigned long dup_start;
		unsigned long dup_stop;
		unsigned long preack_start;
		unsigned long preack_stop;
		unsigned long renege_start;
		unsigned long renege_stop;
		unsigned long burst_start;
		unsigned long burst_stop;

		int div_bpc;
		int dup_num;
		int preack_amt;
		int renege_amt;
		int renege_growth;
		int burst_num;
};

#endif

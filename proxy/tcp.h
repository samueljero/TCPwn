/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
******************************************************************************/
#ifndef _TCP_H
#define _TCP_H

#include "proto.h"
#include <netinet/tcp.h>
#include <list>
#include <utility>


class tcp_half {
	public:
	uint32_t ip;
	char mac[6];
	uint16_t port;

	bool have_initial_seq;
	bool have_initial_ack;
	
	unsigned long initial_seq;
	unsigned long initial_ack;
	unsigned long high_seq;
	unsigned long high_ack;
	unsigned long window;
	unsigned long pkts;
	uint32_t renege_save;
};

class Injector {
	public:
		Injector(pkt_info pk, Message hdr, inject_info &info);
		~Injector();
		unsigned long GetStop() {return stop;}
		bool Start();
		bool Stop();

	private:
		static void* thread_run(void *arg);
		void _run();
		pthread_t thread;
		bool running;
		bool thread_running;
		pkt_info pk;
		Message ip_payload;
		int method;
		int freq;
		enum direction dir;
		unsigned long start;
		unsigned long stop;
		pthread_mutex_t timeout_mutex;
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
		bool in_pkt_range(unsigned long pkt, unsigned long start, unsigned long stop);
		void update_conn_info(struct tcphdr *tcph, Message hdr, tcp_half &src);
		pkt_info PerformPreAck(pkt_info pk, Message hdr, tcp_half &dst);
		pkt_info PerformRenege(pkt_info pk, Message hdr, tcp_half &src);
		pkt_info PerformDivision(pkt_info pk, Message hdr, tcp_half &old_src);
		pkt_info PerformDup(pkt_info pk, Message hdr);
		pkt_info PerformBurst(pkt_info pk, Message hdr);
		bool BuildPacket(pkt_info &pk, Message &hdr, inject_info &info);
		Message BuildEthHeader(Message pk, char* src, char* dst, int next);
		Message BuildIPHeader(Message pk, uint32_t src, uint32_t dst, int next);
		Message BuildTCPHeader(Message pk, uint16_t src, uint16_t dst, inject_info &info, Message &ip_payload, uint32_t ipsrc, uint32_t ipdst);
		bool StartInjector(inject_info &info);

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
		std::list<std::pair<pkt_info,Message> > burst_pkts;
		pthread_mutex_t burst_mutex;
		std::list<inject_info> injections;
		std::list<Injector*> active_injectors;

		unsigned long total_pkts;
};

#endif

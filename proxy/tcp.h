/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * TCP Congestion Control Proxy: TCP specific attack header
******************************************************************************/
#ifndef _TCP_H
#define _TCP_H

#include "proto.h"
#include <netinet/tcp.h>
#include <list>
#include <utility>

#define TCP_STATE_ERR (-1)
#define TCP_STATE_MIN 0
#define TCP_STATE_UNKNOWN 0
#define TCP_STATE_INIT 1
#define TCP_STATE_SLOW_START 2
#define TCP_STATE_CONG_AVOID 3
#define TCP_STATE_FAST_RECOV 4
#define TCP_STATE_RTO 5
#define TCP_STATE_END 6
#define TCP_STATE_ANY 7
#define TCP_STATE_MAX 7

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
	unsigned long dup;
	uint32_t renege_save;
	uint32_t preack_save;
	uint32_t limit_save;
};

class TCPModifier {
	public:
		virtual ~TCPModifier(){};
		virtual bool shouldApply(unsigned long pktnum, int state) = 0;
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst) = 0;
		virtual bool Stop() = 0;

	protected:
		bool in_pkt_range(unsigned long pkt);
		bool is_state(int active_state);
		pkt_info drop(pkt_info pk);

		unsigned long start;
		unsigned long stop;
		int state;
};

class TCP: public Proto {
	public:
		TCP(uint32_t src, uint32_t dst);
		~TCP();
		virtual pkt_info new_packet(pkt_info pk, Message hdr);
		virtual bool validState(const char* state);
		virtual bool SetState(const char* state);
		virtual bool SetInject(unsigned long start, unsigned long stop, const char* state, inject_info &info);
		virtual bool SetDivision(unsigned long start, unsigned long stop, const char* state, int bytes_per_chunk);
		virtual bool SetDup(unsigned long start, unsigned long stop, const char* state, int num);
		virtual bool SetPreAck(unsigned long start, unsigned long stop, const char* state, int amt, int method);
		virtual bool SetRenege(unsigned long start, unsigned long stop, const char* state, int amt, int growth);
		virtual bool SetBurst(unsigned long start, unsigned long stop, const char* state, int num);
		virtual bool SetForceAck(unsigned long start, unsigned long stop, const char* state, int dir, int amt);
		virtual bool SetLimitAck(unsigned long start, unsigned long stop, const char* state);
		virtual bool SetDrop(unsigned long start, unsigned long stop, const char* state, int p);
		virtual bool Clear();
		virtual bool SetPrint(bool on);
		virtual bool GetDuration(timeval *tm);
		virtual bool GetBytes(unsigned long *bytes);

	private:
		pkt_info process_packet(pkt_info pk, Message hdr, tcp_half &src, tcp_half &dst);
		void init_conn_info(pkt_info pk, struct tcphdr *tcph, tcp_half &src, tcp_half &dst);
		void update_conn_info(struct tcphdr *tcph, Message hdr, tcp_half &src);
		void update_conn_times(struct tcphdr *tcph, Message msg, pkt_info pk);
		int normalize_state(const char *s);

		bool do_print;
		tcp_half fwd;
		tcp_half rev;
		unsigned long total_pkts;
		unsigned long total_bytes;
		int protocol_state;
		/* Lists already protected by locks in Attacker */
		std::list<TCPModifier*> mod1;
		std::list<TCPModifier*> mod2;
		timeval start;
		timeval end;
		timeval last;
		pthread_mutex_t lock;
};

class TCPDiv: public TCPModifier {
	public:
		TCPDiv(unsigned long start, unsigned long stop, int state, int div_bpc);
		virtual ~TCPDiv() {}
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}
	
	private:
		int div_bpc;
};

class TCPDup: public TCPModifier {
	public:
		TCPDup(unsigned long start, unsigned long stop, int state, int dup_num);
		virtual ~TCPDup() {}
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}

	private:
		int dup_num;
};

class TCPPreAck: public TCPModifier {
	public:
		TCPPreAck(unsigned long start, unsigned long stop, int state, int preack_amt, int preack_method);
		virtual ~TCPPreAck(){}
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}

	private:
		int preack_amt;
		int preack_method;
		timeval last;
};

class TCPLimitAck: public TCPModifier {
	public:
		TCPLimitAck(unsigned long start, unsigned long stop, int state);
		virtual ~TCPLimitAck(){}
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}

	private:
		bool active;
		unsigned long limit;
};

class TCPDrop: public TCPModifier {
	public:
		TCPDrop(unsigned long start, unsigned long stop, int state, int p);
		virtual ~TCPDrop(){}
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}

	private:
		int p;
		unsigned int rdata;
};

class TCPRenege: public TCPModifier {
	public:
		TCPRenege(unsigned long start, unsigned long stop, int state, int renege_amt, int renege_growth);
		virtual ~TCPRenege(){}
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}

	private:
		int renege_amt;
		int renege_growth;
};

class TCPBurst: public TCPModifier {
	public:
		TCPBurst(unsigned long start, unsigned long stop, int state, int burst_num);
		~TCPBurst();
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop() {return true;}

	private:
		void FinishBurst();
		std::list<std::pair<pkt_info,Message> > burst_pkts;
		pthread_mutex_t burst_mutex;
		int burst_num;
};

class TCPInject: public TCPModifier {
	public:
		TCPInject(unsigned long start, unsigned long stop, int state, inject_info &info);
		~TCPInject();
		virtual bool shouldApply(unsigned long pktnum, int state);
		virtual pkt_info apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst);
		virtual bool Stop();

	private:
		bool Start();
		bool BuildPacket(pkt_info &pk, Message &hdr, inject_info &info);
		Message BuildEthHeader(Message pk, char* src, char* dst, int next);
		Message BuildIPHeader(Message pk, uint32_t src, uint32_t dst, int next);
		Message BuildTCPHeader(Message pk, uint16_t src, uint16_t dst, inject_info &info, Message &ip_payload, uint32_t ipsrc, uint32_t ipdst);
		static void* thread_run(void *arg);
		void _run();

		inject_info info;
		pkt_info pk;
		Message msg;
		tcp_half* fwd;
		tcp_half* rev;

		pthread_t thread;
		bool running;
		bool thread_running;
		pthread_mutex_t timeout_mutex;
};

#endif

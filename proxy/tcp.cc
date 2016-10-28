/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * TCP Congestion Control Proxy: TCP specific attack code
 *****************************************************************************/
#include "proxy.h"
#include "attacker.h"
#include "tcp.h"
#include "iface.h"
#include "args.h"
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/time.h>
using namespace std;

#define TCP_ALIAS_UNKNOWN "STATE_UNKNOWN"
#define TCP_ALIAS_INIT "STATE_INIT"
#define TCP_ALIAS_SLOW_START "STATE_SLOW_START"
#define TCP_ALIAS_CONG_AVOID "STATE_CONG_AVOID"
#define TCP_ALIAS_FAST_RECOV "STATE_FAST_RECOV"
#define TCP_ALIAS_RTO "STATE_RTO"
#define TCP_ALIAS_END "STATE_END"

/* Handle Sequence Wrap */
static int seq_before(uint32_t s1, uint32_t s2)
{
	return (int32_t)(s2 - s1) > 0;
}

#define SEQ_BEFORE(s1, s2) (s1 != s2 && seq_before(s1,s2))
#define SEQ_AFTER(s1, s2) (s1 != s2 && !seq_before(s1,s2))
#define SEQ_BEFOREQ(s1, s2) (s1 == s2 || seq_before(s1,s2))
#define SEQ_AFTERQ(s1, s2) (s1 == s2 || !seq_before(s1,s2))

static bool is_pure_ack(struct tcphdr* tcph, Message hdr)
{
	return (tcph->th_flags & TH_ACK) && 
			!(tcph->th_flags & TH_SYN) &&
			!(tcph->th_flags & TH_FIN) &&
			!(tcph->th_flags & TH_RST) &&
			tcph->th_off*4 == hdr.len;
}


TCP::TCP(uint32_t src, uint32_t dst)
{
	memset(&fwd,0,sizeof(tcp_half));
	memset(&rev,0,sizeof(tcp_half));
	fwd.ip = src;
	fwd.have_initial_seq = false;
	fwd.have_initial_ack = false;
	rev.ip = dst;
	rev.have_initial_seq = false;
	rev.have_initial_ack = false;
	total_pkts = 0;
	protocol_state = TCP_STATE_UNKNOWN;
	do_print = false;
	pthread_mutex_init(&lock, NULL);
}

TCP::~TCP()
{
	pthread_mutex_destroy(&lock);
}

pkt_info TCP::new_packet(pkt_info pk, Message hdr)
{
	if (pk.dir == FORWARD) {
		return process_packet(pk, hdr, fwd, rev);
	} else  if (pk.dir == BACKWARD) {
		return process_packet(pk, hdr, rev, fwd);
	}

	return pk;
}

bool TCP::validState(const char* state)
{
	if (normalize_state(state) == TCP_STATE_ERR) {
		return false;
	}
	return true;
}

pkt_info TCP::process_packet(pkt_info pk, Message hdr, tcp_half &src, tcp_half &dst)
{
	tcp_half old_src;
	struct tcphdr *tcph;
	bool mod = false;

	/* Sanity checks */
	if (hdr.len < (int)sizeof(tcphdr)) {
		return pk;
	}
	tcph = (struct tcphdr*)hdr.buff;
	if (tcph->th_off*4 > hdr.len) {
		return pk;
	}

	/* Initialize addresses and ports */
	if (dst.port == 0) {
		if (tcph->th_flags & TH_SYN) {
			init_conn_info(pk,tcph,src,dst);
			dbgprintf(1, "Connection: src: %i, dst: %i\n", src.port, dst.port);
		} else {
			dbgprintf(1, "Skipping packet from unknown connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
			return pk;
		}
	}

	/* Ignore packets from unexpected ports */
	if (ntohs(tcph->th_sport) != src.port ||
	    ntohs(tcph->th_dport) != dst.port) {
		dbgprintf(1, "Skipping packet from other connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
		return pk;
	}

	memcpy(&old_src,&src,sizeof(tcp_half));
	update_conn_info(tcph,hdr,src);
	update_conn_times(tcph,hdr,pk);

	/* debug printing */
	if (do_print) {
		dbgprintf(0,"#%u: %u:%i -> %u:%i, seq: %u, ack: %u\n",
				total_pkts,src.ip,src.port,dst.ip,dst.port,
				ntohl(tcph->th_seq),ntohl(tcph->th_ack));
	}


	/* We don't care about data-bearing packets */
	if (!is_pure_ack(tcph,hdr)) {
		return pk;
	}

	/* Check all actions */
	for (list<TCPModifier*>::iterator it = mod1.begin(); it != mod1.end(); it++) {
		if ((*it)->shouldApply(total_pkts, protocol_state)) {
			pk = (*it)->apply(pk,hdr,src,old_src,dst);
			mod = true;
		}
	}
	for (list<TCPModifier*>::iterator it = mod2.begin(); it != mod2.end(); it++) {
		if ((*it)->shouldApply(total_pkts, protocol_state)) {
			pk = (*it)->apply(pk,hdr,src,old_src,dst);
		}
	}

	if (mod && pk.valid && pk.msg.buff) {
		Attacker::get().fixupAndSend(pk,hdr,true);
		free(pk.msg.buff);
		pk.msg.buff = NULL;
		pk.msg.len = 0;
		pk.valid = false;
		pk.ip_src = pk.ip_dst = NULL;
		pk.mac_src = pk.mac_dst = NULL;
	}

	return pk;
}

void TCP::init_conn_info(pkt_info pk, struct tcphdr *tcph, tcp_half &src, tcp_half &dst)
{
	if (pk.ip_src && pk.ip_dst && pk.ip_type == 4) {
		memcpy(&src.ip, pk.ip_src, 4);
		memcpy(&dst.ip, pk.ip_dst, 4);
	}

	if (pk.mac_src && pk.mac_dst) {
		memcpy(&src.mac, pk.mac_src,6);
		memcpy(&dst.mac, pk.mac_dst,6);
	}

	src.port = ntohs(tcph->th_sport);
	dst.port = ntohs(tcph->th_dport);

	pthread_mutex_lock(&lock);
	memcpy((char*)&start, (char*)&pk.time, sizeof(timeval));
	memcpy((char*)&end, (char*)&pk.time, sizeof(timeval));
	memcpy((char*)&last, (char*)&pk.time, sizeof(timeval));
	pthread_mutex_unlock(&lock);
}

void TCP::update_conn_info(struct tcphdr *tcph, Message hdr, tcp_half &src)
{
	int len;

	/* Handle ISNs */
	if (!src.have_initial_seq) {
		src.initial_seq = ntohl(tcph->th_seq);
		src.high_seq = ntohl(tcph->th_seq);
		src.have_initial_seq = true;
	}
	if (!src.have_initial_ack && (tcph->th_flags & TH_ACK)) {
		src.initial_ack = ntohl(tcph->th_ack);
		src.high_ack = ntohl(tcph->th_ack);
		src.have_initial_ack = true;
	}

	/* Update sequence and ack numbers */
	//TODO: How do we handle SACK?
	if (src.have_initial_seq && SEQ_AFTER(ntohl(tcph->th_seq),src.high_seq) && !(tcph->th_flags & TH_SYN)) {
		len = hdr.len - tcph->th_off*4 - 1;
		src.high_seq = ntohl(tcph->th_seq) + len;
	}
	if (src.have_initial_ack && (tcph->th_flags & TH_ACK) && SEQ_AFTERQ(ntohl(tcph->th_ack),src.high_ack)) {
		src.high_ack = ntohl(tcph->th_ack);
		if (ntohl(tcph->th_ack) == src.high_ack) {
			src.dup++;
		} else {
			src.dup = 0;
		}
	}

	/* Update Window */
	//TODO: Window Scale Option
	src.window = ntohs(tcph->th_win);

	/* Update pkt count */
	src.pkts++;
	total_pkts++;

	//dbgprintf(2,"Stats: initial_seq: %u, high_seq: %u, inital_ack: %u, high_ack: %u, window: %i, pkts: %u\n",
	//		src.initial_seq, src.high_seq, src.initial_ack, src.high_ack, src.window, total_pkts);
}

void TCP::update_conn_times(struct tcphdr *tcph, Message msg, pkt_info pk)
{
	int len = (msg.len -tcph->th_off*4);
	if (len > 0) {
		pthread_mutex_lock(&lock);
		timeval diff;
		timersub(&last, &pk.time, &diff);
		if (diff.tv_sec <= 0) {
			memcpy((char*)&end, (char*) &pk.time, sizeof(timeval));
		}
		memcpy((char*)&last, (char*) &pk.time, sizeof(timeval));
		total_bytes += len;
		pthread_mutex_unlock(&lock);
	}
}

int TCP::normalize_state(const char *s)
{
	int ret;
	if (s[0] == '*') {
		return TCP_STATE_ANY;
	}

	if (is_int(s)) {
		ret = atoi(s);
		if (ret < TCP_STATE_MIN || ret > TCP_STATE_MAX) return TCP_STATE_ERR;
		return ret;
	}
	if (!strcmp(TCP_ALIAS_UNKNOWN,s)) return TCP_STATE_UNKNOWN;
	if (!strcmp(TCP_ALIAS_INIT,s)) return TCP_STATE_INIT;
	if (!strcmp(TCP_ALIAS_SLOW_START,s)) return TCP_STATE_SLOW_START;
	if (!strcmp(TCP_ALIAS_CONG_AVOID,s)) return TCP_STATE_CONG_AVOID;
	if (!strcmp(TCP_ALIAS_FAST_RECOV,s)) return TCP_STATE_FAST_RECOV;
	if (!strcmp(TCP_ALIAS_RTO,s)) return TCP_STATE_RTO;
	if (!strcmp(TCP_ALIAS_END,s)) return TCP_STATE_END;
	return TCP_STATE_ERR;
}

bool TCP::SetInject(unsigned long start, unsigned long stop, const char* state, inject_info &info)
{
	TCPModifier *m = new TCPInject(start,stop,normalize_state(state),info);
	mod2.push_back(m);
	return true;
}

bool TCP::SetDivision(unsigned long start, unsigned long stop, const char* state, int bytes_per_chunk)
{
	TCPModifier *m = new TCPDiv(start,stop,normalize_state(state),bytes_per_chunk);
	mod2.push_back(m);
	return true;
}

bool TCP::SetDup(unsigned long start, unsigned long stop, const char* state, int num)
{
	TCPModifier *m = new TCPDup(start,stop,normalize_state(state),num);
	mod2.push_back(m);
	return true;
}

bool TCP::SetPreAck(unsigned long start, unsigned long stop, const char* state, int amt, int method)
{
	TCPModifier *m = new TCPPreAck(start,stop,normalize_state(state),amt,method);
	mod1.push_back(m);
	return true;
}

bool TCP::SetRenege(unsigned long start, unsigned long stop, const char* state, int amt, int growth)
{
	TCPModifier *m = new TCPRenege(start,stop,normalize_state(state),amt,growth);
	mod1.push_back(m);
	return true;
}

bool TCP::SetBurst(unsigned long start, unsigned long stop, const char* state, int num)
{
	TCPModifier *m = new TCPBurst(start,stop,normalize_state(state),num);
	mod2.push_back(m);
	return true;
}

bool TCP::SetForceAck(unsigned long start, unsigned long stop, const char* state, int dir, int amt)
{
	inject_info info;
	
	memset(&info,0,sizeof(inject_info));
	info.dir = (enum direction)dir;
	info.method = METHOD_ID_REL;
	info.freq = 0;
	info.num = 1;
	info.ack = amt;
	info.seq = 0;
	info.window = 0;
	if (start == 0) {
		start = 4;
	}
	info.type = TH_ACK;
	info.start = start;
	info.stop = stop;
	info.state = normalize_state(state);
	return SetInject(start,stop,state,info);
}

bool TCP::SetLimitAck(unsigned long start, unsigned long stop, const char* state)
{
	TCPModifier *m = new TCPLimitAck(start,stop,normalize_state(state));
	mod1.push_back(m);
	return true;
}
bool TCP::SetDrop(unsigned long start, unsigned long stop, const char* state, int p)
{
	TCPModifier *m = new TCPDrop(start,stop,normalize_state(state),p);
	mod2.push_back(m);
	return true;
}

bool TCP::Clear()
{
	for (list<TCPModifier*>::iterator it = mod1.begin(); it != mod1.end(); it++) {
		(*it)->Stop();
		delete (*it);
	}
	for (list<TCPModifier*>::iterator it = mod2.begin(); it != mod2.end(); it++) {
		(*it)->Stop();
		delete (*it);
	}
	mod1.clear();
	mod2.clear();
	return true;
}

bool TCP::SetPrint(bool on)
{
	do_print = on;
	return true;
}

bool TCP::GetDuration(timeval *tm) 
{
	if (tm == NULL) {
		return false;
	}

	pthread_mutex_lock(&lock);
	timersub(&end, &start, tm);
	pthread_mutex_unlock(&lock);

	return true;
}

bool TCP::GetBytes(unsigned long *bytes)
{
	if (bytes == NULL) {
		return false;
	}
	pthread_mutex_lock(&lock);
	*bytes = total_bytes;
	pthread_mutex_unlock(&lock);

	return true;
}

bool TCP::SetState(const char* state)
{
	int tmp;
	if ((tmp = normalize_state(state)) == TCP_STATE_ERR) {
		return false;
	}
	protocol_state = tmp;
	return true;
}

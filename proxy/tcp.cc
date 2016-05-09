/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 *****************************************************************************/
#include "proxy.h"
#include "attacker.h"
#include "tcp.h"
#include "iface.h"
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/time.h>
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

static bool is_pure_ack(struct tcphdr* tcph, Message hdr)
{
	return (tcph->th_flags & TH_ACK) && 
			!(tcph->th_flags & TH_SYN) &&
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
	renege_save = 0;

	do_div = do_dup = do_preack = false;
	do_renege = do_burst = do_print = false;
}

TCP::~TCP()
{

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

	/* Initialize addresses if needed */
	if (dst.port == 0) {
		init_conn_info(pk,tcph,src,dst);		
	}

	memcpy(&old_src,&src,sizeof(tcp_half));
	update_conn_info(tcph,src);

	/* debug printing */
	if (do_print) {
		dbgprintf(0,"%u:%i -> %u:%i, seq: %u, ack: %u\n",
				src.ip,src.port,dst.ip,dst.port,
				ntohl(tcph->seq),ntohl(tcph->ack));
	}


	/* We don't care about data-bearing packets */
	if (!is_pure_ack(tcph,hdr)) {
		return pk;
	}

	if (do_preack && in_pkt_range(total_pkts,preack_start,preack_stop)) {
		pk = PerformPreAck(pk,hdr,dst);
		mod = true;
	} else if (do_renege && in_pkt_range(total_pkts,renege_start,renege_stop)) {
		pk = PerformRenege(pk,hdr);
		mod = true;
	}

	if (do_div && in_pkt_range(total_pkts,div_start,div_stop)) {
		pk = PerformDivision(pk,hdr,old_src);
	} else if (do_dup && in_pkt_range(total_pkts,div_start,div_stop)) {
		pk = PerformDup(pk,hdr);
	} else if (do_burst && in_pkt_range(total_pkts,burst_start,burst_stop)) {
		pk = PerformBurst(pk,hdr);
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

bool TCP::in_pkt_range(unsigned long pkt, unsigned long start, unsigned long stop)
{
	if (pkt >= start && stop == 0) {
		return true;
	}
	return pkt >= start && pkt < stop;
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
}

void TCP::update_conn_info(struct tcphdr *tcph, tcp_half &src)
{
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
	if (src.have_initial_seq && SEQ_AFTER(ntohl(tcph->th_seq),src.high_seq)) {
		src.high_seq = ntohl(tcph->th_seq);
	}
	if (src.have_initial_ack && (tcph->th_flags & TH_ACK) && SEQ_AFTER(ntohl(tcph->th_ack),src.high_ack)) {
		src.high_ack = ntohl(tcph->th_ack);
	}

	/* Update Window */
	//TODO: Window Scale Option
	src.window = ntohs(tcph->th_win);

	/* Update pkt count */
	src.pkts++;
	total_pkts++;

	/* Check scheduled injections */
	for (list<inject_info>::iterator it = injections.begin(); it != injections.end(); it++) {
		if (it->start == total_pkts) {
			inject_info tmp;
			memcpy(&tmp,&(*it),sizeof(inject_info));
			StartInjector(tmp);
		}
	}
	for (list<Injector*>::iterator it = active_injectors.begin(); it != active_injectors.end(); it++) {
		if ((*it)->GetStop() == total_pkts) {
			(*it)->Stop();
		}
	}
}

pkt_info TCP::PerformPreAck(pkt_info pk, Message hdr, tcp_half &dst)
{
	struct tcphdr *tcph;
	uint32_t ack;

	tcph = (struct tcphdr*)hdr.buff;

	ack = ntohl(tcph->th_ack);
	if (SEQ_AFTER((uint32_t)ack + preack_amt, dst.high_seq)) {
		tcph->ack = htonl(dst.high_seq);
	} else {
		tcph->ack = htonl(ack+preack_amt);
	}

	return pk;
}

pkt_info TCP::PerformRenege(pkt_info pk, Message hdr)
{
	struct tcphdr *tcph;
	uint32_t ack;

	tcph = (struct tcphdr*)hdr.buff;
	
	ack = ntohl(tcph->th_ack);
	if (renege_growth == 1) {
		/* Keep reneging */
		if (!renege_save) {
			renege_save = ack - renege_amt;
			tcph->ack = htonl(renege_save);
		} else {
			renege_save = renege_save - renege_amt;
			tcph->ack = htonl(renege_save);
		}
	} else {
		/* Constant negative offset */
		tcph->ack = htonl(ack-renege_amt);
	}

	return pk;
}

pkt_info TCP::PerformDivision(pkt_info pk, Message hdr, tcp_half &old_src)
{
	struct tcphdr *tcph;
	uint32_t ack;
	int diff;
	int bpc;

	tcph = (struct tcphdr*)hdr.buff;
	ack = ntohl(tcph->th_ack);

	/* Only divide new acks */
	if (ack < old_src.high_ack) {
		return pk;
	}

	/* Sequence range to divide */
	diff = seq_diff(ack,old_src.high_ack);

	/* Do division */
	ack = old_src.high_ack;
	while(diff > 0) {
		/* chunks must be smaller than remaining sequence space to ack */
		if (diff > div_bpc) {
			bpc = diff;
		} else {
			bpc = div_bpc;
		}

		/* do increment */
		ack += bpc;
		diff -= bpc;

		/* Set ACK */
		tcph->th_ack = htonl(ack);

		/* Send */
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

pkt_info TCP::PerformDup(pkt_info pk, Message hdr)
{
	for(int i = 0; i < dup_num; i++) {
		/* Send */
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

pkt_info TCP::PerformBurst(pkt_info pk, Message hdr)
{
	burst_pkts.push_back(make_pair(pk,hdr));

	if ((int)burst_pkts.size() >= burst_num) {
		for (list<pair<pkt_info,Message> >::iterator it = burst_pkts.begin(); it != burst_pkts.end(); it++) {
			/* Send */
			Attacker::get().fixupAndSend(it->first, it->second, true);

			/* Cleanup */
			free(it->first.msg.buff);
			it->first.msg.buff = NULL;
		}

		burst_pkts.clear();
	}

	/* Release packet */
	pk.msg.buff = NULL;
	pk.msg.len = 0;
	pk.valid = false;
	pk.ip_src = pk.ip_dst = NULL;

	return pk;
}


bool TCP::SetInject(unsigned long start, unsigned long stop, inject_info &info)
{
	info.start = start;
	info.stop = stop;

	if (start == 0 || (start <= total_pkts && stop > total_pkts)) {
		if(!StartInjector(info)) {
			return false;
		}
	} else {
		injections.push_back(info);
	}

	return true;
}

bool TCP::StartInjector(inject_info &info)
{
	Injector *inj;
	pkt_info pk;
	Message hdr;

	if (!BuildPacket(pk,hdr,info)) {
		dbgprintf(0, "Error: Failed to build packet!\n");
		return false;
	}

	inj = new Injector(pk,hdr, info);
	if (!inj->Start()) {
		dbgprintf(0, "Error:Failed to start injector!\n");
		return false;
	}
	active_injectors.push_back(inj);

	return true;
}

bool TCP::BuildPacket(pkt_info &pk, Message &hdr, inject_info &info)
{
	char src_mac[6];
	char dst_mac[6];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	Message next;

	/* Validate Addresses */
	if (fwd.ip != 0 && fwd.port != 0 && rev.ip != 0 && rev.port != 0) {
		/* Already received pkts, can grab addresses */
		if (info.dir == FORWARD) {
			memcpy(src_mac,fwd.mac,6);
			memcpy(dst_mac,rev.mac,6);
			src_ip = fwd.ip;
			dst_ip = rev.ip;
			src_port = fwd.port;
			dst_port = rev.port;
		} else if (info.dir == BACKWARD) {
			memcpy(src_mac,rev.mac,6);
			memcpy(dst_mac,fwd.mac,6);
			src_ip = rev.ip;
			dst_ip = fwd.ip;
			src_port = rev.port;
			dst_port = fwd.port;
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
	next = BuildTCPHeader(next, src_port, dst_port, info, hdr);

	/* Fixup checksums, etc */
	pk = Attacker::get().fixupAndSend(pk,hdr,false);

	return true;
}

Message TCP::BuildEthHeader(Message pk, char* src, char* dst, int next)
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

Message TCP::BuildIPHeader(Message pk, uint32_t src, uint32_t dst, int next)
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

Message TCP::BuildTCPHeader(Message pk, uint16_t src, uint16_t dst, inject_info &info, Message &ip_payload)
{
	struct tcphdr *tcph;

	tcph = (struct tcphdr*)pk.buff;
	tcph->th_sport = htons(src);
	tcph->th_dport = htons(dst);
	tcph->th_seq = htonl(info.seq);
	tcph->th_ack = htonl(info.ack);
	tcph->th_x2 = 0;
	tcph->th_off = 5;
	tcph->th_flags = info.type;
	tcph->th_win = htons(info.window);
	tcph->th_sum = 0;
	tcph->th_urp = 0;

	ip_payload = pk;
	ip_payload.len = sizeof(struct tcphdr);

	pk.buff += sizeof(struct tcphdr);
	pk.len -= sizeof(struct tcphdr);

	return pk;
}

bool TCP::SetDivision(unsigned long start, unsigned long stop, int bytes_per_chunk)
{
	div_start = start;
	div_stop = stop;
	div_bpc = bytes_per_chunk;
	do_div = true;
	return true;
}

bool TCP::SetDup(unsigned long start, unsigned long stop, int num)
{
	dup_start = start;
	dup_stop = stop;
	dup_num = num;
	do_dup = true;
	return true;
}

bool TCP::SetPreAck(unsigned long start, unsigned long stop, int amt)
{
	preack_start = start;
	preack_stop = stop;
	preack_amt = amt;
	do_preack = true;
	return true;
}

bool TCP::SetRenege(unsigned long start, unsigned long stop, int amt, int growth)
{
	renege_start = start;
	renege_stop = stop;
	renege_amt = amt;
	renege_growth = growth;
	do_renege = true;
	return true;
}

bool TCP::SetBurst(unsigned long start, unsigned long stop, int num)
{
	burst_start = start;
	burst_stop = stop;
	burst_num = num;
	do_burst = true;
	return true;
}

bool TCP::Clear()
{
	do_div = do_dup = do_preack = do_renege = false;
	do_burst = do_print = false;
	return true;
}

bool TCP::SetPrint(bool on)
{
	do_print = on;
	return true;
}

Injector::Injector(pkt_info pk, Message hdr, inject_info &info)
{
	this->pk = pk;
	this->ip_payload = hdr;
	this->method = info.method;
	this->freq = info.freq;
	this->dir = info.dir;
	this->start = info.start;
	this->stop = info.stop;
	this->running = false;
	this->thread_running = false;
	pthread_mutex_init(&this->timeout_mutex, NULL);
}

Injector::~Injector()
{
	pthread_mutex_destroy(&this->timeout_mutex);
}

bool Injector::Start()
{
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
void* Injector::thread_run(void* arg)
{
	Injector *t = (Injector*)arg;
	t->_run();
	t->thread_running = false;
	return NULL;
}

void Injector::_run()
{
	struct timespec time;
	struct timeval tm;
	int sec;
	int nsec;
	int val;

	/* Mutex used only to sleep on */
	pthread_mutex_lock(&timeout_mutex);

	while(running) {
		if (pk.snd) {
			pk.snd->sendm(pk.msg);
		}

		/* Compute time to send */
		sec = freq / 1000;
		nsec = (freq % 1000)*1000000;
		gettimeofday(&tm, NULL);
		time.tv_sec = 0;
		time.tv_nsec = tm.tv_usec*1000 + nsec;
		if (time.tv_nsec > 1000000000) {
			time.tv_sec += time.tv_nsec/1000000000;
			time.tv_nsec = time.tv_nsec%1000000000;
		}
		time.tv_sec += (tm.tv_sec + sec);

		/* Sleep */
		val = pthread_mutex_timedlock(&timeout_mutex, &time);
		if (val != ETIMEDOUT) {
			continue;
		}
	}
}

bool Injector::Stop() {
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

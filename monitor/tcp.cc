/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * Congestion Control Sender Monitor: TCP specific code
 *****************************************************************************/
#include "tcp.h"
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

TCP::TCP()
{
	this->tcp_data_pkts = 0;
	this->tcp_data_bytes = 0;
	this->tcp_ack_pkts = 0;
	this->tcp_ack_bytes = 0;
	this->tcp_ack_dup = 0;
	this->tcp1_seq_low = 0;
	this->tcp1_seq_high = 0;
	this->tcp1_ack_low = 0;
	this->tcp1_ack_high = 0;
	this->tcp1_port = 0;
	this->tcp2_seq_low = 0;
	this->tcp2_seq_high = 0;
	this->tcp2_ack_low = 0;
	this->tcp2_ack_high = 0;
	this->tcp2_port = 0;
	this->state = TCP_STATE_UNKNOWN;
	memset(ip1str, 0, INET_ADDRSTRLEN);
	memset(ip2str, 0, INET_ADDRSTRLEN);
}

TCP::~TCP(){}

bool TCP::new_packet(pkt_info pk, Message hdr)
{
	struct tcphdr *tcph;
	bool ret = true;

	/* Sanity checks */
	if (pk.msg.buff == NULL) {
		return false;
	}
	if (hdr.len < (int)sizeof(tcphdr)) {
		return false;
	}
	tcph = (struct tcphdr*)hdr.buff;
	if (tcph->th_off*4 > hdr.len) {
		return false;
	}


	pthread_rwlock_rdlock(&lock);

	if (tcp1_port == 0 && tcp2_port == 0) {
		if (tcph->th_flags & TH_SYN) {
			pthread_rwlock_unlock(&lock);
			pthread_rwlock_wrlock(&lock);
			tcp1_port = ntohs(tcph->th_sport);
			tcp2_port = ntohs(tcph->th_dport);
			if (pk.ip_type == 4 && pk.ip_src != NULL && pk.ip_dst != NULL) {
				memcpy(&ip1, pk.ip_src, sizeof(uint32_t));
				memcpy(&ip2, pk.ip_dst, sizeof(uint32_t));
				resolveIP2str(ip1,ip1str,INET_ADDRSTRLEN);
				resolveIP2str(ip2,ip2str,INET_ADDRSTRLEN);
			}
			dbgprintf(1, "Connection: src: %i, dst: %i\n", tcp1_port, tcp2_port);
		} else {
			dbgprintf(1, "Skipping packet from unknown connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
			ret = false;
			goto out;
		}
	}

	if ((tcp1_port != ntohs(tcph->th_sport) || tcp2_port != ntohs(tcph->th_dport)) &&
	    (tcp2_port != ntohs(tcph->th_sport) || tcp1_port != ntohs(tcph->th_dport)) ) {
		dbgprintf(1, "Skipping packet from other connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
		ret = false;
		goto out;
	}
	updateTCPVars(hdr);

out:
	pthread_rwlock_unlock(&lock);
	return ret;
}

void TCP::updateTCPVars(Message hdr)
{
	struct tcphdr *tcph;
	tcph = (struct tcphdr*)hdr.buff;

	/* Set State INIT on SYN */
	if (tcph->th_flags & TH_SYN) {
		state = TCP_STATE_START;
		return;
	}

	/* Set State END on FIN/RST */
	if ((tcph->th_flags & TH_FIN) ||
	    (tcph->th_flags & TH_RST)) {
		state = TCP_STATE_END;
		return;
	}
	if (state == TCP_STATE_END) {
		return;
	}

	/* Sanity */
	if (!(tcph->th_flags & TH_ACK)) {
		return;
	}

	/* Is data bearing packet */
	if (hdr.len > tcph->th_off*4) {
		tcp_data_pkts++;
	} else {
		tcp_ack_pkts++;
	}

	if (tcp1_port == ntohs(tcph->th_sport)) {
			if (tcp1_seq_high == 0 || SEQ_AFTER(ntohl(tcph->th_seq),(uint32_t)tcp1_seq_high)) {
				if (tcp1_seq_high != 0 && hdr.len > tcph->th_off*4) {
					tcp_data_bytes += (hdr.len - tcph->th_off*4);
				}
				tcp1_seq_high = ntohl(tcph->th_seq) + (hdr.len - tcph->th_off*4);
			}

			if (hdr.len == tcph->th_off*4 && ntohl(tcph->th_ack) == tcp1_ack_high) {
				tcp_ack_dup++;
			}

			if (tcp1_ack_high == 0 || SEQ_AFTER(ntohl(tcph->th_ack), (uint32_t)tcp1_ack_high)) {
				if (tcp1_ack_high != 0) {
					tcp_ack_bytes += seq_diff(ntohl(tcph->th_ack),(uint32_t)tcp1_ack_high);
				}
				tcp1_ack_high = ntohl(tcph->th_ack);
			}

			if (SEQ_BEFORE(ntohl(tcph->th_seq), (uint32_t)tcp1_seq_high)) {
				tcp_retransmits++;
			}
	} else {
			if (tcp2_seq_high == 0 || SEQ_AFTER(ntohl(tcph->th_seq),(uint32_t)tcp2_seq_high)) {
				if (tcp2_seq_high != 0 && hdr.len > tcph->th_off*4) {
					tcp_data_bytes += (hdr.len - tcph->th_off*4);
				}
				tcp2_seq_high = ntohl(tcph->th_seq);
			}
			
			if (hdr.len == tcph->th_off*4 && ntohl(tcph->th_ack) == tcp2_ack_high) {
				tcp_ack_dup++;
			}

			if (tcp2_ack_high == 0 || SEQ_AFTER(ntohl(tcph->th_ack), (uint32_t)tcp2_ack_high)) {
				if (tcp2_ack_high != 0) {
					tcp_ack_bytes += seq_diff(ntohl(tcph->th_ack),(uint32_t)tcp2_ack_high);
				}
				tcp2_ack_high = ntohl(tcph->th_ack);
			}

			if (SEQ_BEFORE(ntohl(tcph->th_seq), (uint32_t)tcp2_seq_high)) {
				tcp_retransmits++;
			}
	}
	return;
}

void TCP::resetCtrs()
{
	tcp_ack_pkts = 0;
	tcp_ack_bytes = 0;
	tcp_ack_dup = 0;
	tcp_data_pkts = 0;
	tcp_data_bytes = 0;
	tcp_retransmits = 0;
}

void TCP::setAckHolds()
{
	tcp1_ack_hold = tcp2_seq_high + 1;
	tcp2_ack_hold = tcp1_seq_high + 1;
}

bool TCP::areAckHoldsPassed()
{
	return tcp1_ack_high <= tcp1_ack_hold && tcp2_ack_high <= tcp2_ack_hold;
}


void TCP::resolveIP2str(uint32_t ip, char* str, int len)
{
	inet_ntop(AF_INET,&ip,str,len);
}

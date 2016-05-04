/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 *****************************************************************************/
#include "proxy.h"
#include "attacker.h"
#include "tcp.h"
#include <netinet/tcp.h>
using namespace std;


TCP::TCP(uint32_t src, uint32_t dst)
{
	memset(&fwd,0,sizeof(tcp_half));
	memset(&rev,0,sizeof(tcp_half));
	fwd.ip = src;
	rev.ip = dst;

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
	struct tcphdr *tcph;

	/* Sanity checks */
	if (hdr.len < (int)sizeof(tcphdr)) {
		return pk;
	}
	tcph = (struct tcphdr*)hdr.buff;
	if (tcph->th_off*4 > hdr.len) {
		return pk;
	}

	/* Initialize addresses if needed */
	if (dst.ip == 0) {
		init_conn_info(pk,tcph,src,dst);		
	}

	if (pk.ip_src && hdr.buff) {
		return pk;
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

	src.port = tcph->th_sport;
	dst.port = tcph->th_dport;
}

bool TCP::SetInject(unsigned long start, unsigned long stop, inject_info &info)
{
	if (start > 0 && stop > 0 && info.mac_src != NULL) {
		return true;
	}
	return false;
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

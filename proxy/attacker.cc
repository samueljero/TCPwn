/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu> and Xiangyu Bu <xb@purdue.edu>
* TCP Congestion Control Proxy: Malicious Processing
******************************************************************************/
#include "attacker.h"
#include "csv.h"
#include "args.h"
#include "checksums.h"
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <map>
#include <list>
#include <vector>
#include <string>
using namespace std;

#define ATTACKER_ROW_NUM_FIELDS		7
#define ATTACKER_ARGS_DELIM		'&'

#define PKT_TYPES_STR_LEN		5000

pthread_mutex_t ofo_print_serialization_mutex = PTHREAD_MUTEX_INITIALIZER;

Attacker::Attacker()
{
	pthread_rwlock_init(&lock, NULL);
}
Attacker::~Attacker()
{
	pthread_rwlock_destroy(&lock);
}

Attacker& Attacker::get()
{
	static Attacker me;
	return me;
}

bool Attacker::addCommand(Message m, Message *resp)
{
	bool ret = true;
	size_t num_fields;
	int action_type;
	char **fields;
	arg_node_t *args;

	dbgprintf(2, "Received CMD: %s\n", m.buff);

	/* Parse CSV */
	fields = csv_parse(m.buff, m.len, &num_fields);
	for (size_t i = 0; i < num_fields; ++i) {
		csv_unescape(fields[i]);
		fprintf(stderr, "%lu: \"%s\"\n", i, fields[i]);
	}

	if (num_fields != ATTACKER_ROW_NUM_FIELDS) {
		dbgprintf(0,"Adding Command: csv field count mismatch (%lu / %d).\n", num_fields, ATTACKER_ROW_NUM_FIELDS);
		ret = false;
		goto out;
	}

	if ((action_type = normalize_action_type(fields[5])) == ACTION_ID_ERR) {
		dbgprintf(0,"Adding Command: unsupported malicious action \"%s\".\n", fields[5]);
		ret = false;
		goto out;
	}

	args = args_parse(fields[6],ATTACKER_ARGS_DELIM);
	if (!args) {
		dbgprintf(0,"Adding Command: failed to parse arguments \"%s\"\n", fields[6]);
		ret = false;
		goto out;
	}

	//Actually load stuff

	args_free(args);
out:
	csv_free(fields);
	return ret;
}

int Attacker::normalize_action_type(char *s)
{
	int ret;
	if (is_int(s)) {
		ret = atoi(s);
		if (ret < ACTION_ID_MIN || ret > ACTION_ID_MAX) return ACTION_ID_ERR;
		return ret;
	}
	return ACTION_ID_ERR;
}



pkt_info Attacker::doAttack(pkt_info pk)
{
	pthread_rwlock_rdlock(&lock);

	if (proxy_debug > 2) {
		print(pk);
	}

	pk = parseEthernet(pk);

	pthread_rwlock_unlock(&lock);
	return pk;
}

pkt_info Attacker::parseEthernet(pkt_info pk)
{
	struct ether_header *eth;

	if (pk.msg.len < (int)sizeof(struct ether_header)) { //Check packet length
		return pk;
	}
	eth = (struct ether_header*)pk.cur.buff;
	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			pk.cur.buff = pk.cur.buff + sizeof(struct ether_header);
			pk.cur.len = pk.cur.len - sizeof(struct ether_header);
			pk = parseIPv4(pk);
			break;
		case ETHERTYPE_IPV6:
		case ETHERTYPE_VLAN:
		default:
			return pk;
	}

	return pk;
}

pkt_info Attacker::parseIPv4(pkt_info pk)
{
	struct iphdr *ip;
	char *save;

	if (pk.cur.len < (int) sizeof(struct iphdr)) { //Check packet length
		return pk;
	}

	save = pk.cur.buff;
	ip = (struct iphdr*)pk.cur.buff;
	if (ip->version != 4) { //Check IP version
		return pk;
	}
	if (ip->ihl*4 > pk.cur.len) { //Check claimed header length
		return pk;
	}

	pk.cur.buff = pk.cur.buff + ip->ihl*4;
	pk.cur.len = pk.cur.len - ip->ihl*4;
	pk.ip_type = 4;
	pk.ip_src = (char*) &ip->saddr;
	pk.ip_dst = (char*) &ip->daddr;

	switch(ip->protocol) {
		case 6: //TCP
			//pk=
			break;
		default:
			return pk;
	}

	/* Update packet length */
	pk.cur.len += ip->ihl*4;
	pk.cur.buff = save;

	/*Adjust IPv4 header to account for packet's total length*/
	ip->tot_len=htons(pk.cur.len + ip->ihl*4);

	/* Compute IPv4 Checksum */
	ip->check = 0;
	ip->check = ipv4_chksum((u_char*)save, ip->ihl*4);

	return pk;
}

pkt_info Attacker::parseIPv6(pkt_info pk)
{
	struct ip6_hdr *ip;
	char *save;

	if (pk.cur.len < (int) sizeof(struct ip6_hdr)) { //Check packet length
		return pk;
	}

	save = pk.cur.buff;
	ip = (struct ip6_hdr*) pk.cur.buff;
	if((ntohl(ip->ip6_ctlun.ip6_un1.ip6_un1_flow) & (0xF0000000)) != (60000000)){ //Check IP version
		return pk;
	}

	pk.cur.buff = pk.cur.buff + sizeof(struct ip6_hdr);
	pk.cur.len  = pk.cur.len - sizeof(struct ip6_hdr);
	pk.ip_type = 6;
	pk.ip_src = (char*) &ip->ip6_src;
	pk.ip_dst = (char*) &ip->ip6_dst;

	switch(ip->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
		case 6: //TCP
		default:
			return pk;
	}

	/* Adjust IPv6 header length */
	ip->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(pk.cur.len);

	pk.cur.len += sizeof(struct ip6_hdr);
	pk.cur.buff = save;
	return pk;
}

void Attacker::print(pkt_info pk)
{
	pthread_mutex_lock(&ofo_print_serialization_mutex);
	dbgprintf(0,"Packet in direction: %d\n", pk.dir);
	pthread_mutex_unlock(&ofo_print_serialization_mutex);
}

bool Attacker::start()
{
	return true;
}

bool Attacker::stop()
{
	return true;
}

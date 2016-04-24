/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu> and Xiangyu Bu <xb@purdue.edu>
* TCP Congestion Control Proxy: Malicious Processing
******************************************************************************/
#include "attacker.h"
#include "iface.h"
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
	Message m;

	pthread_rwlock_rdlock(&lock);

	if (proxy_debug > 2) {
		print(pk);
	}

	m = pk.msg;
	pk = parseEthernet(pk, m);

	pthread_rwlock_unlock(&lock);
	return pk;
}

pkt_info Attacker::fixupAndSend(pkt_info pk, Message ip_payload, bool dosend)
{
	Message m;

	if (!pk.valid || !pk.msg.buff) {
		dbgprintf(0, "Error: Trying to send invalid packet\n");
	}

	m = fixupEthernet(pk.msg,ip_payload);
	
	if (m.buff != pk.msg.buff || m.len > pk.msg.alloc || !pk.snd) {
		dbgprintf(0, "Error: Trying to send invalid packet\n");
		pk.valid = false;
		pk.msg.buff = NULL;
		return pk;
	}
	pk.msg = m;

	if (dosend) {
		pk.snd->sendm(pk.msg);
	}
	return pk;
}

pkt_info Attacker::parseEthernet(pkt_info pk, Message cur)
{
	struct ether_header *eth;
	Message m;

	/* Check packet length */
	if (pk.msg.len < (int)sizeof(struct ether_header)) {
		return pk;
	}
	if (cur.len < (int)sizeof(struct ether_header)) {
		return pk;
	}
	eth = (struct ether_header*)cur.buff;
	pk.mac_src = (char*) &eth->ether_shost;
	pk.mac_dst = (char*) &eth->ether_dhost;

	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			m.buff = cur.buff + sizeof(struct ether_header);
			m.len = cur.len - sizeof(struct ether_header);
			pk = parseIPv4(pk, m);
			break;
		case ETHERTYPE_IPV6:
		case ETHERTYPE_VLAN:
		default:
			return pk;
	}

	return pk;
}

Message Attacker::fixupEthernet(Message cur, Message ip_payload)
{
	struct ether_header *eth;
	Message m;

	/* Check packet length */
	if (cur.len < (int)sizeof(struct ether_header)) {
			m.buff = NULL;
			m.len = m.alloc = 0;
			return m;
	}

	eth = (struct ether_header*)cur.buff;
	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			m.buff = cur.buff + sizeof(struct ether_header);
			m.len = cur.len - sizeof(struct ether_header);
			m = fixupIPv4(m, ip_payload);
			break;
		case ETHERTYPE_IPV6:
		case ETHERTYPE_VLAN:
		default:
			m.buff = NULL;
			m.len = m.alloc = 0;
			return m;
	}

	/* Fixup buffer lengths */
	m.buff = cur.buff;
	m.len = m.len + sizeof(struct ether_header);
	return m;
}

pkt_info Attacker::parseIPv4(pkt_info pk, Message cur)
{
	struct iphdr *ip;
	Message m;

	/* Check packet length */
	if (cur.len < (int) sizeof(struct iphdr)) {
		return pk;
	}

	ip = (struct iphdr*)cur.buff;
	/* Check IP version */
	if (ip->version != 4) {
		return pk;
	}
	/* Check claimed header length */
	if (ip->ihl*4 > cur.len) {
		return pk;
	}

	m.buff = cur.buff + ip->ihl*4;
	m.len = cur.len - ip->ihl*4;
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
	return pk;
}

Message Attacker::fixupIPv4(Message cur, Message ip_payload)
{
	struct iphdr *ip;
	Message m;

	/* Check packet length*/
	if (cur.len < (int) sizeof(struct iphdr)) {
		m.buff = NULL;
		m.len = m.alloc = 0;
		return m;
	}

	ip = (struct iphdr*)cur.buff;
	/* Check IP version */
	if (ip->version != 4) {
		m.buff = NULL;
		m.len = m.alloc = 0;
		return m;
	}
	/* Check claimed header length */
	if (ip->ihl*4 > cur.len) {
		m.buff = NULL;
		m.len = m.alloc = 0;
		return m;
	}

	m.buff = cur.buff + ip->ihl*4;
	m.len = cur.len - ip->ihl*4;
	/* Check that IP payload starts where it should */
	if (m.buff != ip_payload.buff) {
		m.buff = NULL;
		m.len = m.alloc = 0;
		return m;
	}

	/* Update packet length */
	cur.len = ip_payload.len + ip->ihl*4;

	/*Adjust IPv4 header to account for packet's total length*/
	ip->tot_len=htons(ip_payload.len + ip->ihl*4);

	/* Compute IPv4 Checksum */
	ip->check = 0;
	ip->check = ipv4_chksum((u_char*)cur.buff, ip->ihl*4);

	return cur;
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

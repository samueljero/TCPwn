/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu> and Xiangyu Bu <xb@purdue.edu>
*
* Rule Format:
* src_ip,dst_ip,proto
******************************************************************************/
#include "tracker.h"
#include "iface.h"
#include "csv.h"
#include "args.h"
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
#include <climits>
using namespace std;

#define ATTACKER_ROW_NUM_FIELDS		7
#define ATTACKER_ARGS_DELIM		'&'

#define PROTO_ALIAS_TCP			"TCP"

#define IP_WILDCARD 0

#define TIME_ERROR ULONG_MAX

#define PKT_TYPES_STR_LEN		5000

Tracker::Tracker()
{
	pthread_rwlock_init(&lock, NULL);
}
Tracker::~Tracker()
{
	pthread_rwlock_destroy(&lock);
}

Tracker& Tracker::get()
{
	static Tracker me;
	return me;
}

bool Tracker::addCommand(Message m, Message *resp)
{
	bool ret = true;
	size_t num_fields;
	int action_type;
	int proto;
	unsigned long start;
	unsigned long stop;
	uint32_t ip_src;
	uint32_t ip_dst;
	char **fields;
	arg_node_t *args;

	dbgprintf(2, "Received CMD: %s\n", m.buff);

	/* Parse CSV */
	fields = csv_parse(m.buff, m.len, &num_fields);

	if (num_fields != ATTACKER_ROW_NUM_FIELDS) {
		dbgprintf(0,"Adding Command: csv field count mismatch (%lu / %d).\n", num_fields, ATTACKER_ROW_NUM_FIELDS);
		ret = false;
		goto out;
	}

	ip_src = normalize_addr(fields[0]);
	ip_dst = normalize_addr(fields[1]);

	if ((proto = normalize_proto(fields[2])) == PROTO_ID_ERR) {
		dbgprintf(0,"Adding Command: unsupported protocol \"%s\".\n", fields[3]);
		ret = false;
		goto out;
	}

	if ((start = normalize_time(fields[3])) == TIME_ERROR) {
		dbgprintf(0,"Adding Command: invalid start time \"%s\".\n", fields[4]);
		ret = false;
		goto out;
	}

	if ((stop = normalize_time(fields[4])) == TIME_ERROR) {
		dbgprintf(0,"Adding Command: invalid end time \"%s\".\n", fields[4]);
		ret = false;
		goto out;
	}
	if ( stop != 0 && stop < start) {
		dbgprintf(0,"Adding Command: end time before start time.\n");
		ret = false;
		goto out;
	}

	if ((action_type = normalize_action_type(fields[5])) == ACTION_ID_ERR) {
		dbgprintf(0,"Adding Command: unsupported malicious action \"%s\".\n", fields[5]);
		ret = false;
		goto out;
	}
	if (ip_src == IP_WILDCARD || ip_dst == IP_WILDCARD) {
		dbgprintf(0,"Adding Command: bad addresses \"%s\", \"%s\"\n", fields[0],fields[1]);
		ret = false;
		goto out;
	}

	args = args_parse(fields[6],ATTACKER_ARGS_DELIM);
	if (!args) {
		dbgprintf(0,"Adding Command: failed to parse arguments \"%s\"\n", fields[6]);
		ret = false;
		goto out;
	}

	pthread_rwlock_wrlock(&lock);

	/* Process this action for this connection */
	if (ret) {
		dbgprintf(1, "New Rule Installed: %u -> %u (%i), %lu -> %lu, %i\n", ip_src, ip_dst, proto, start, stop, action_type);
	}

	if (resp) {
		resp = NULL;
	}

	/*release lock*/
	pthread_rwlock_unlock(&lock);
	args_free(args);
out:
	csv_free(fields);
	return ret;
}

int Tracker::normalize_action_type(char *s)
{
	int ret;
	if (is_int(s)) {
		ret = atoi(s);
		if (ret < ACTION_ID_MIN || ret > ACTION_ID_MAX) return ACTION_ID_ERR;
		return ret;
	}
	return ACTION_ID_ERR;
	return 0;
}

int Tracker::normalize_proto(char *s)
{
	int ret;
	if (is_int(s)) {
		ret = atoi(s);
		if (ret < PROTO_ID_MIN || ret > PROTO_ID_MAX) return PROTO_ID_ERR;
		return ret;
	}

	if (!strcmp(PROTO_ALIAS_TCP,s)) return PROTO_ID_TCP;
	return PROTO_ID_ERR;
}

uint32_t Tracker::normalize_addr(char *s)
{
	struct addrinfo hints;
	struct addrinfo *results, *p;
	struct sockaddr_in *v4;
	uint32_t res;

	if (s[0] == '*') {
		return IP_WILDCARD;
	}

	/* Lookup IP/Hostname */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	if (getaddrinfo(s, NULL, &hints, &results) < 0) {
		return IP_WILDCARD;
	}

	for (p = results; p!=NULL; p = p->ai_next) {
		v4 = (struct sockaddr_in*)p->ai_addr;
		res = v4->sin_addr.s_addr;
		return res;
	}

	return IP_WILDCARD;
}

bool Tracker::normalize_mac(char* str, char* raw)
{
	char *ptr = str;
	char *end = str;
	int tmp;
	int byte = 0;

	while (*end != 0 && byte < 6) {
		tmp = strtol(ptr,&end,16);
		if (*end != ':' && *end != 0) {
			return false;
		}

		raw[byte] = tmp;
		byte++;
		ptr = end + 1;
	}

	if (byte != 6) {
		return false;
	}

	return true;
}

unsigned long Tracker::normalize_time(char *s)
{
	unsigned long t;
	char *end;

	t = strtoul(s,&end,0);
	if (end == s) {
		return TIME_ERROR;
	}

	return t;
}

pkt_info Tracker::track(pkt_info pk)
{
	Message m;

	pthread_rwlock_rdlock(&lock);

	if (monitor_debug > 2) {
		print(pk);
	}

	m = pk.msg;
	parseEthernet(pk, m);

	pthread_rwlock_unlock(&lock);
	return pk;
}

void Tracker::parseEthernet(pkt_info pk, Message cur)
{
	struct ether_header *eth;
	Message m;

	/* Check packet length */
	if (pk.msg.len < (int)sizeof(struct ether_header)) {
		return;
	}
	if (cur.len < (int)sizeof(struct ether_header)) {
		return;
	}
	eth = (struct ether_header*)cur.buff;
	pk.mac_src = (char*) &eth->ether_shost;
	pk.mac_dst = (char*) &eth->ether_dhost;

	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			m.buff = cur.buff + sizeof(struct ether_header);
			m.len = cur.len - sizeof(struct ether_header);
			parseIPv4(pk, m);
			break;
		case ETHERTYPE_IPV6:
		case ETHERTYPE_VLAN:
		default:
			return;
	}

	return;
}

void Tracker::parseIPv4(pkt_info pk, Message cur)
{
	struct iphdr *ip;
	Message m;

	/* Check packet length */
	if (cur.len < (int) sizeof(struct iphdr)) {
		return;
	}

	ip = (struct iphdr*)cur.buff;
	/* Check IP version */
	if (ip->version != 4) {
		return;
	}
	/* Check claimed header length */
	if (ip->ihl*4 > cur.len) {
		return;
	}

	m.buff = cur.buff + ip->ihl*4;
	m.len = cur.len - ip->ihl*4;
	pk.ip_type = 4;
	pk.ip_src = (char*) &ip->saddr;
	pk.ip_dst = (char*) &ip->daddr;

	switch(ip->protocol) {
		case 6: //TCP
			updateClassicCongestionControl(pk, m);
			break;
		default:
			return;
	}
	return;
}

void Tracker::updateClassicCongestionControl(pkt_info pk, Message cur) {
	if (pk.ip_src && cur.len > 0) {

	}
	return;
}

void Tracker::print(pkt_info pk)
{
	dbgprintf(0,"Packet in direction: %d\n", pk.dir);
}

bool Tracker::start()
{
	return true;
}

bool Tracker::stop()
{
	return true;
}

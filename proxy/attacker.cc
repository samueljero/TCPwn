/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu> and Xiangyu Bu <xb@purdue.edu>
* TCP Congestion Control Proxy: Malicious Processing
*
* Rule Format:
* src_ip,dst_ip,proto,start,stop,state,action,parms
******************************************************************************/
#include "attacker.h"
#include "iface.h"
#include "csv.h"
#include "args.h"
#include "checksums.h"
#include "proto.h"
#include "tcp.h"
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

#define ATTACKER_ROW_NUM_FIELDS		8
#define ATTACKER_ARGS_DELIM		'&'

#define ACTION_ALIAS_ACTIVE		"ACTIVE"
#define ACTION_ALIAS_TIME		"TIME"
#define ACTION_ALIAS_STATE		"STATE"
#define ACTION_ALIAS_INJECT 	"INJECT"
#define ACTION_ALIAS_DIV 		"DIV"
#define ACTION_ALIAS_DUP		"DUP"
#define ACTION_ALIAS_PREACK		"PREACK"
#define ACTION_ALIAS_RENEGE		"RENEGE"
#define ACTION_ALIAS_BURST		"BURST"
#define ACTION_ALIAS_PRINT		"PRINT"
#define ACTION_ALIAS_CLEAR		"CLEAR"

#define PROTO_ALIAS_TCP			"TCP"

#define METHOD_ALIAS_ABS		"ABS"

#define IP_WILDCARD 0

#define TIME_ERROR ULONG_MAX

#define PKT_TYPES_STR_LEN		5000

pthread_mutex_t ofo_print_serialization_mutex = PTHREAD_MUTEX_INITIALIZER;

Attacker::Attacker()
{
	ipv4_id = 42;
	pthread_rwlock_init(&lock, NULL);
	pthread_mutex_init(&time_lock, NULL);
	gettimeofday(&last_pkt, NULL);
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
	int proto;
	unsigned long start;
	unsigned long stop;
	uint32_t ip_src;
	uint32_t ip_dst;
	char **fields;
	arg_node_t *args;
	Proto *obj;
	arg_node_t *targ;
	int amt;
	inject_info info;
	char *state;

	dbgprintf(2, "Received CMD: %s\n", m.buff);

	/* Parse CSV */
	fields = csv_parse(m.buff, m.len, &num_fields);
	/*for (size_t i = 0; i < num_fields; ++i) {
		csv_unescape(fields[i]);
		fprintf(stderr, "%lu: \"%s\"\n", i, fields[i]);
	}*/

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

	state = fields[5];

	if ((action_type = normalize_action_type(fields[6])) == ACTION_ID_ERR) {
		dbgprintf(0,"Adding Command: unsupported malicious action \"%s\".\n", fields[5]);
		ret = false;
		goto out;
	}

	args = args_parse(fields[7],ATTACKER_ARGS_DELIM);
	if (!args) {
		dbgprintf(0,"Adding Command: failed to parse arguments \"%s\"\n", fields[6]);
		ret = false;
		goto out;
	}

	/* Is there current activity? */
	if (ip_src == IP_WILDCARD && ip_dst == IP_WILDCARD && action_type == ACTION_ID_ACTIVE) {
		/* We don't need the lock here! */
		last_packet(resp);
		goto cleanargs;
	}

	/*take lock */
	pthread_rwlock_wrlock(&lock);

	/* Clear ALL rules and state */
	if (ip_src == IP_WILDCARD && ip_dst == IP_WILDCARD && action_type == ACTION_ID_CLEAR) {
		clear_connections();
		goto unlock;
	}

	/* Find or create object for this connection */
	if (ip_src == IP_WILDCARD || ip_dst == IP_WILDCARD) {
		dbgprintf(0,"Adding Command: bad addresses \"%s\", \"%s\"\n", fields[0],fields[1]);
		ret = false;
		goto unlock;
	}
	if ((obj = find_or_create_proto(ip_src,ip_dst,proto)) == NULL) {
		dbgprintf(0,"Adding Command: failed to find/create object for connection");
		ret = false;
		goto unlock;
	}
	
	/* Validate state */
	if (!obj->validState(state)) {
		dbgprintf(0,"Adding Command: invalid protocol state \"%s\"\n", state);
		ret = false;
		goto unlock;
	}

	/* Process this action for this connection */
	switch(action_type) {
		case ACTION_ID_INJECT:
			memset(&info,0,sizeof(inject_info));

			targ = args_find(args, "mac_src");
			if (targ) {
				strncpy(info.mac_src, targ->value.s, MAC_MAX);
			}

			targ = args_find(args, "mac_dst");
			if (targ) {
				strncpy(info.mac_dst, targ->value.s, MAC_MAX);
			}

			strncpy(info.ip_src, fields[0], IP_MAX);
			strncpy(info.ip_dst, fields[1], IP_MAX);

			targ = args_find(args, "src_port");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				info.port_src = targ->value.i;
			}

			targ = args_find(args, "dst_port");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				info.port_dst = targ->value.i;
			}

			targ = args_find(args, "type");
			if (targ && targ-> type == ARG_VALUE_TYPE_INT) {
				info.type = targ->value.i;
			}

			targ = args_find(args, "win");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				info.window = targ->value.i;
			}

			targ = args_find(args, "seq");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				info.seq = targ->value.i;
			}

			targ = args_find(args, "ack");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				info.ack = targ->value.i;
			}

			targ = args_find(args, "freq");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				info.freq = targ->value.i;
			}

			targ = args_find(args, "dir");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				if (targ->value.i == 1) {
					info.dir = FORWARD;
				} else if (targ->value.i == 2) {
					info.dir = BACKWARD;
				} else {
					dbgprintf(0, "Adding INJECT Command: failed with bad arguments---invalid direction\n");
				}
			} else {
					dbgprintf(0, "Adding INJECT Command: failed with bad arguments---invalid direction\n");
			}

			targ = args_find(args, "method");
			if (targ) {
				info.method = normalize_method(targ->value.s);
			}

			if (start == 0 && ( !info.mac_src || !info.mac_dst ||
				info.port_src == 0 || info.port_dst == 0)) {
				dbgprintf(0, "Adding INJECT Command: failed with bad arguments---start is zero and no addresses\n");
				ret = false;
			} else {
				ret = obj->SetInject(start,stop,state,info);
			}
			break;
		case ACTION_ID_DIV:
			targ = args_find(args, "bpc");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				ret = obj->SetDivision(start,stop,state,targ->value.i);
			} else {
				dbgprintf(0, "Adding DIV Command: failed with bad arguments (missing bpc tag)\n");
				ret = false;
			}
			break;
		case ACTION_ID_DUP:
			targ = args_find(args, "num");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				ret = obj->SetDup(start,stop,state,targ->value.i);
			} else {
				dbgprintf(0, "Adding DUP Command: failed with bad arguments (missing num tag)\n");
				ret = false;
			}
			break;
		case ACTION_ID_PREACK:
			targ = args_find(args, "amt");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				amt = targ->value.i;
				targ = args_find(args, "method");
				if (targ && targ->type == ARG_VALUE_TYPE_INT) {
					ret = obj->SetPreAck(start, stop, state, amt, targ->value.i);
				} else {
					dbgprintf(0, "Adding PREACK Command: failed with bad arguments (missing method tag)\n");
					ret = false;
				}
			} else {
				dbgprintf(0, "Adding PREACK Command: failed with bad arguments (missing amt tag)\n");
				ret = false;
			}
			break;
		case ACTION_ID_RENEGE:
			targ = args_find(args,"amt");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				amt = targ->value.i;
				targ = args_find(args, "growth");
				if (targ && targ->type == ARG_VALUE_TYPE_INT) {
					ret = obj->SetRenege(start,stop,state,amt,targ->value.i);
				} else {
					dbgprintf(0, "Adding RENEGE Command: failed with bad arguments (missing growth tag)\n");
					ret = false;
				}
			} else {
				dbgprintf(0, "Adding RENEGE Command: failed with bad arguments (missing amt tag)\n");
				ret = false;
			}
			break;
		case ACTION_ID_BURST:
			targ = args_find(args,"num");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				ret = obj->SetBurst(start,stop,state,targ->value.i);
			} else {
				dbgprintf(0, "Adding BURST Command: failed with bad arguments (missing num tag)\n");
				ret = false;
			}
			break;
		case ACTION_ID_PRINT:
			targ = args_find(args, "on");
			if (targ && targ->type == ARG_VALUE_TYPE_INT) {
				ret = obj->SetPrint(targ->value.i);
			} else {
				dbgprintf(0, "Adding PRINT Command: failed with bad arguments (missing on tag)\n");
				ret = false;
			}
			break;
		case ACTION_ID_CLEAR:
			obj->Clear();
			goto unlock;
			break;
		case ACTION_ID_TIME:
			get_conn_duration(obj, resp);
			goto unlock;
			break;
		case ACTION_ID_STATE:
			obj->SetState(state);
			goto unlock;
			break;
	}

	if (ret) {
		dbgprintf(1, "New Rule Installed: %u -> %u (%i), %lu -> %lu, %i\n", ip_src, ip_dst, proto, start, stop, action_type);
	}

unlock:
	/*release lock*/
	pthread_rwlock_unlock(&lock);
cleanargs:
	args_free(args);
out:
	csv_free(fields);
	return ret;
}

Proto* Attacker::find_or_create_proto(uint32_t src, uint32_t dst, int proto)
{
	map<uint32_t, map<uint32_t,Proto*> >::iterator it1;
	Proto *obj = NULL;

	obj = find_proto(src,dst);
	if (obj) {
		return obj;
	}
	obj = find_proto(dst,src);
	if (obj) {
		return obj;
	}

	obj = create_proto(src,dst,proto);

	/* Insert forward */
	it1 = connections.find(src);
	if (it1 == connections.end()) {
		connections[src] = map<uint32_t,Proto*>();
		connections[src][dst] = obj;
	} else {
		connections[src][dst] = obj;
	}

	/* Insert backward */
	it1 = connections.find(dst);
	if (it1 == connections.end()) {
		connections[dst] = map<uint32_t,Proto*>();
		connections[dst][src] = obj;
	} else {
		connections[dst][src] = obj;
	}

	return obj;
}

Proto *Attacker::find_proto(uint32_t src, uint32_t dst)
{
	map<uint32_t, map<uint32_t,Proto*> >::iterator it1;
	map<uint32_t,Proto* >::iterator it2;

	it1 = connections.find(src);
	if (it1 == connections.end()) {
		return NULL;
	}

	it2 = it1->second.find(dst);
	if (it2 == it1->second.end()) {
		return NULL;
	}

	return it2->second;
}

Proto *Attacker::create_proto(uint32_t src, uint32_t dst, int proto)
{
	Proto * obj;
	switch(proto) {
		case PROTO_ID_TCP:
			obj = new TCP(src,dst);
			return obj;
	}
	return NULL;
}

bool Attacker::clear_connections()
{
	uint32_t src;
	uint32_t dst;

	while (connections.begin() != connections.end()) {
		if (connections.begin()->second.begin() == connections.begin()->second.end()) {
			connections.erase(connections.begin());
		} else {
			src = connections.begin()->first;
			dst = connections.begin()->second.begin()->first;
			if (connections.begin()->second.begin()->second) {
				connections.begin()->second.begin()->second->Clear();
				delete connections.begin()->second.begin()->second;
				connections[dst][src] = NULL;
			}
			connections.begin()->second.erase(connections.begin()->second.begin());
		}
	}

	dbgprintf(1, "Data cleared!\n");
	return true;
}

int Attacker::normalize_action_type(char *s)
{
	int ret;
	if (is_int(s)) {
		ret = atoi(s);
		if (ret < ACTION_ID_MIN || ret > ACTION_ID_MAX) return ACTION_ID_ERR;
		return ret;
	}
	if (!strcmp(ACTION_ALIAS_ACTIVE,s)) return ACTION_ID_ACTIVE;
	if (!strcmp(ACTION_ALIAS_TIME,s)) return ACTION_ID_TIME;
	if (!strcmp(ACTION_ALIAS_STATE,s)) return ACTION_ID_STATE;
	if (!strcmp(ACTION_ALIAS_INJECT,s)) return ACTION_ID_INJECT;
	if (!strcmp(ACTION_ALIAS_DIV,s)) return ACTION_ID_DIV;
	if (!strcmp(ACTION_ALIAS_DUP,s)) return ACTION_ID_DUP;
	if (!strcmp(ACTION_ALIAS_PREACK,s)) return ACTION_ID_PREACK;
	if (!strcmp(ACTION_ALIAS_RENEGE,s)) return ACTION_ID_RENEGE;
	if (!strcmp(ACTION_ALIAS_BURST,s)) return ACTION_ID_BURST;
	if (!strcmp(ACTION_ALIAS_PRINT,s)) return ACTION_ID_PRINT;
	if (!strcmp(ACTION_ALIAS_CLEAR,s)) return ACTION_ID_CLEAR;
	return ACTION_ID_ERR;
}

int Attacker::normalize_proto(char *s)
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

int Attacker::normalize_method(char *s)
{
	int ret;
	if (is_int(s)) {
		ret = atoi(s);
		if (ret < METHOD_ID_MIN || ret > METHOD_ID_MAX) return METHOD_ID_ERR;
		return ret;
	}

	if (!strcmp(METHOD_ALIAS_ABS,s)) return METHOD_ID_ABS;
	return METHOD_ID_ERR;
}

uint32_t Attacker::normalize_addr(char *s)
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

bool Attacker::normalize_mac(char* str, char* raw)
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

unsigned long Attacker::normalize_time(char *s)
{
	unsigned long t;
	char *end;

	t = strtoul(s,&end,0);
	if (end == s) {
		return TIME_ERROR;
	}

	return t;
}

pkt_info Attacker::doAttack(pkt_info pk)
{
	Message m;

	pthread_rwlock_rdlock(&lock);

	gettimeofday(&pk.time, NULL);
	if (pthread_mutex_trylock(&time_lock) == 0) {
		memcpy((char*)&last_pkt, (char*)&pk.time, sizeof(timeval));
		pthread_mutex_unlock(&time_lock);
	}

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
		return pk;
	}

	m = fixupEthernet(pk.msg,ip_payload);
	
	if (m.buff != pk.msg.buff || m.len > pk.msg.alloc || !pk.snd) {
		dbgprintf(0, "Error: Trying to send invalid packet--\n");
		pk.valid = false;
		pk.msg.buff = NULL;
		return pk;
	}
	pk.msg = m;

	if (dosend) {
		pk.snd->sendm(pk.msg, true);
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
	m.alloc = cur.alloc;
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
			pk= check_connection(pk, m);
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

	/*Set IP ID */
	ip->id = ipv4_id++; 

	/* Update packet length */
	cur.len = ip_payload.len + ip->ihl*4;

	/*Adjust IPv4 header to account for packet's total length*/
	ip->tot_len=htons(ip_payload.len + ip->ihl*4);

	/* Compute IPv4 Checksum */
	ip->check = 0;
	ip->check = ipv4_chksum((u_char*)cur.buff, ip->ihl*4);

	return cur;
}

pkt_info Attacker::check_connection(pkt_info pk, Message cur)
{
	uint32_t src;
	uint32_t dst;
	map<uint32_t,map<uint32_t,Proto*> >::iterator it1;
	map<uint32_t,Proto*>::iterator it2;

	if (!pk.ip_src || !pk.ip_dst) {
		return pk;
	}
	memcpy(&src, pk.ip_src, sizeof(src));
	memcpy(&dst, pk.ip_dst, sizeof(dst));

	it1 = connections.find(src);
	if (it1 != connections.end()) {
		it2 = it1->second.find(dst);
		if (it2 != it1->second.end()) {
			return it2->second->new_packet(pk,cur);
		}
	}

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

void Attacker::last_packet(Message *res)
{
	if (res == NULL) {
		return;
	}

	res->alloc = 100;
	res->buff = (char*) malloc(res->alloc);
	if (res->buff == NULL) {
		dbgprintf(0, "Error: Cannot allocate memmory!\n");
		res->alloc = 0;
		return;
	}

	pthread_mutex_lock(&time_lock);

	res->len = snprintf(res->buff,res->alloc, "%ld.%06ld\n", last_pkt.tv_sec, last_pkt.tv_usec);

	pthread_mutex_unlock(&time_lock);
	return;
}

void Attacker::get_conn_duration(Proto *obj, Message *res)
{
	timeval tm;
	unsigned long bytes;

	if (obj == NULL || res == NULL) {
		return;
	}

	memset((char*)&tm,0,sizeof(timeval));
	obj->GetDuration(&tm);
	obj->GetBytes(&bytes);

	
	res->alloc = 100;
	res->buff = (char*) malloc(res->alloc);
	if (res->buff == NULL) {
		dbgprintf(0, "Error: Cannot allocate memmory!\n");
		res->alloc = 0;
		return;
	}

	res->len = snprintf(res->buff,res->alloc, "%ld.%06ld\n%ld\n", tm.tv_sec, tm.tv_usec, bytes);
	return;
}

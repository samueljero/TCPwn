/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu> and Xiangyu Bu <xb@purdue.edu>
* Congestion Control Sender Monitor: Tracker Module
******************************************************************************/
#include "tracker.h"
#include "iface.h"
#include "proto.h"
#include "algorithm.h"
#include "tcp.h"
#include "classic.h"
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <map>
#include <list>
#include <vector>
#include <string>
#include <climits>
using namespace std;

#define PROTO_ALIAS_TCP			"TCP"
#define ALG_ALIAS_CLASSIC		"classic"

Tracker::Tracker()
{
	alg_id = ALG_ID_CLASSIC;
	proto_id = PROTO_ID_TCP;
	proto = NULL;
	alg = NULL;
	sock = -1;
	pthread_mutex_init(&lock, NULL);
}
Tracker::~Tracker()
{
	if (proto != NULL) {
		stop();
	}
	pthread_mutex_destroy(&lock);
}

Tracker& Tracker::get()
{
	static Tracker me;
	return me;
}

bool Tracker::setAlgorithmAndProtocol(char *alg, char* proto)
{
	int proto_id;
	int alg_id;

	proto_id = normalize_proto(proto);
	if (proto_id == PROTO_ID_ERR) {
		return false;
	}

	alg_id = normalize_algorithm(alg);
	if (alg_id == ALG_ID_ERR) {
		return false;
	}

	return true;
}

int Tracker::is_int(char *v) {
	if (*v == '\0') return 0;
	while (*v != '\0') {
		if (*v < '0' || *v > '9') return 0;
		++v;
	}
	return 1;
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

int Tracker::normalize_algorithm(char *s)
{
	int ret;
	if (is_int(s)) {
		ret = atoi(s);
		if (ret < ALG_ID_MIN || ret > ALG_ID_MAX) return ALG_ID_ERR;
		return ret;
	}

	if (!strcmp(ALG_ALIAS_CLASSIC,s)) return ALG_ID_CLASSIC;
	return ALG_ID_ERR;
}

pkt_info Tracker::track(pkt_info pk)
{
	Message m;

	if (monitor_debug > 2) {
		print(pk);
	}

	m = pk.msg;
	parseEthernet(pk, m);
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
			if (alg && proto && proto->hasIPProto(6)) {
				alg->new_packet(pk,m);
			}
			break;
		default:
			return;
	}
	return;
}

void Tracker::print(pkt_info pk)
{
	dbgprintf(0,"Packet in direction: %d\n", pk.dir);
}


bool Tracker::start()
{
	if (!proto) {
		switch (proto_id) {
			case PROTO_ID_TCP:
				proto = new TCP();
				break;
			default:
				proto = NULL;
		}
		
	}
	if (!alg) {
		switch(alg_id) {
			case ALG_ID_CLASSIC:
				alg = new Classic(proto);
				alg->start();
				break;
			default:
				alg = NULL;
		}

	}
	return true;
}

bool Tracker::stop()
{
	if (alg) {
		alg->stop();
	}
	delete alg;
	alg = NULL;
	delete proto;
	proto = NULL;
	closeOutputSocket();
	return true;
}

bool Tracker::openOutputSocket(struct sockaddr_in &addr)
{
	closeOutputSocket();

	pthread_mutex_lock(&lock);
	memcpy(&output_addr, &addr, sizeof(struct sockaddr_in));

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		dbgprintf(0, "Connection Failed: Could not create sock: %s\n", strerror(errno));
		sock = -1;
	}

	if (sock > 0 && connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0) {
		dbgprintf(0, "Connection Failed: %s\n", strerror(errno));
		close(sock);
		sock = -1;
	}

	if (sock > 0) {
		dbgprintf(1, "Established output connection...\n");
	}

	pthread_mutex_unlock(&lock);
	return sock > 0;
}

bool Tracker::closeOutputSocket()
{
	if (sock != -1) {
		pthread_mutex_lock(&lock);
		close(sock);
		sock = -1;
		pthread_mutex_unlock(&lock);
	}
	return true;
}

void Tracker::sendState(const char *state, const char* ip1, const char* ip2, const char* proto)
{
	char buff[100];
	Message m;

	if (sock < 0) {
		return;
	}

	pthread_mutex_lock(&lock);
	readAndThrowAway();

	

	m.buff = buff;
	m.alloc = 100;
	m.len = 0;
	m.len = snprintf(m.buff,m.alloc,"%s,%s,%s,0,0,%s,STATE,*", ip1, ip2, proto, state);
	if (m.len < 0 || m.len >= m.alloc) {
		goto out;
	}
	if(!sendMsg(m)) {
		close(sock);
		sock = -1;
	}

out:
	pthread_mutex_unlock(&lock);
}

void Tracker::readAndThrowAway()
{
	char buff[32];
	int len;

	while ((len = recv(sock,buff,32,MSG_DONTWAIT)) >= 0) {
		//throwaway
	}

	return;
}

bool Tracker::sendMsg(Message m)
{
	char *buff;
	int len;
	uint16_t len16;
	int ret;

	if (sock <= 0) {
		return false;
	}

	if (m.len > 65533) {
		return false;
	}

	buff = (char*)malloc(m.len + 2);
	if (!buff) {
		dbgprintf(0, "Error: Cannot allocate Memory!\n");
		return false;
	}

	len = m.len + 2;
	len16 = htons(len);
	memcpy(&buff[0], (char*)&len16, 2);
	memcpy(&buff[2], m.buff, m.len);
	ret = send(sock,buff,len,0);
	if (ret < 0) {
		dbgprintf(0, "Error: send() failed: %s\n", strerror(errno));
		free(buff);
		return false;
	}

	free(buff);
	return true;
}

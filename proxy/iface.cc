/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* TCP Congestion Control Proxy: Interface read/write thread
******************************************************************************/
#include "iface.h"
#include "attacker.h"
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
using namespace std;



bool Iface::sendm(Message m, bool allow_drop)
{
	int len;
	int retries = 0;
	if (sock < 0) {
		return false;
	}
	
retry:
	if ((len = send(sock, m.buff, m.len, MSG_NOSIGNAL)) < 0) {
		if (errno == ENOBUFS || errno == ENOMEM) {
			if (allow_drop) {
				dbgprintf(3, "Packet Dropped due to queuing\n");
				return true;
			} else {
				if (retries%1000 == 0) {
					dbgprintf(0, "Send Failed (retry %i): %s\n", retries, strerror(errno));
				}
				retries++;
				pthread_yield();
				goto retry;
			}
		}
		dbgprintf(0, "Send Failed: %s\n", strerror(errno));
		
		_stop();
		return false;
	}

	return true;
}

Iface::Iface() {
	this->sock = -1;
	this->other = NULL;
	this->dir = NONE;
	this->print_messages = false;
	this->rcv_thread_running = false;
	this->rcv_thread_cleanup = false;
	this->running = false;
	this->iface = "";
}

Iface::Iface(std::string interface) {
	this->sock = -1;
	this->other = NULL;
	this->dir = NONE;
	this->print_messages = false;
	this->rcv_thread_running = false;
	this->rcv_thread_cleanup = false;
	this->running = false;
	this->iface = interface;
}



Iface::~Iface() {}

bool Iface::start()
{
	struct ifreq ifr;
	struct sockaddr_ll sll;
	struct packet_mreq mr;

	if (other == NULL) {
		return false;
	}

	if (sock >= 0) {
		return false;
	}

	sock = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL));
	if (sock < 0) {
		dbgprintf(0, "Opening Interface Failed: Could not create socket: %s\n", strerror(errno));
		sock = -1;
		return false;
	}

	strncpy ((char *) ifr.ifr_name, iface.c_str(), IFNAMSIZ);
	if (ioctl(sock, SIOCGIFINDEX, &ifr)<0) {
		dbgprintf(0, "Opening Interface Failed: Could not configure socket: %s\n", strerror(errno));
		close(sock);
		sock = -1;
		return false;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock,(struct sockaddr*) &sll, sizeof(sll)) < 0 ) {
		dbgprintf(0, "Opening Interface Failed: Could not configure socket: %s\n", strerror(errno));
		close(sock);
		sock = -1;
		return false;
	}

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0 ) {
		dbgprintf(0, "Opening Interface Failed: Could not configure socket: %s\n", strerror(errno));
		close(sock);
		sock = -1;
		return false;
	}

	running = true;
	if (pthread_create(&rcv_thread, NULL, rcv_thread_run, this) < 0) {
		dbgprintf(0, "Error: Failed to start receive thread!: %s\n", strerror(errno));
		close(sock);
		sock = -1;
		running = false;
		return false;
	}
	rcv_thread_running = true;
	rcv_thread_cleanup = true;
	return true;
}

bool Iface::stop()
{
	_stop();

	if (rcv_thread_cleanup) {
		rcv_thread_cleanup = false;
		pthread_join(rcv_thread, NULL);
	}

	return true;
}

bool Iface::_stop()
{
	if (running) {
			running = false;
	}
	if (sock >= 0) {
		close(sock);
		sock = -1;
	}

	return true;
}

/* stupid pthreads/C++ glue */
void* Iface::rcv_thread_run(void* arg)
{
	Iface *t = (Iface*)arg;
	t->rcv_run();
	t->rcv_thread_running = false;
	return NULL;
}

void Iface::rcv_run()
{
	pkt_info pk;

	while (running) {
		pk.msg = recvMsg();
		if (pk.msg.buff == NULL){
			running = false;
			if (other->isRunning()) {
				other->_stop();
			}
			break;
		}

		pk.valid = true;
		pk.dir = this->dir;
		pk.rcv = this;
		pk.snd = this->other;
		pk.ip_type = 0;
		pk.ip_src = NULL;
		pk.ip_dst = NULL;
		pk.mac_src = NULL;
		pk.mac_dst = NULL;
		pk = Attacker::get().doAttack(pk);

		if (!pk.valid) {
			/* No message to send */
			continue;
		}
		if (pk.msg.buff == NULL) {
			/* No message to send */
			continue;
		}
		if (!pk.snd) {
			/* No interface to send on */
			free(pk.msg.buff);
			memset(&pk,0,sizeof(pkt_info));
			continue;
		}

		/* Send message */
		if(!pk.snd->sendm(pk.msg, true)) {
			_stop();
			break;
		}

		free(pk.msg.buff);
		memset(&pk,0,sizeof(pkt_info));
	}
}


Message Iface::recvMsg()
{
	Message m;

	m.alloc = 1600;
	m.len = 0;
	m.buff =(char*) malloc(m.alloc);
	if (m.buff == NULL) {
		m.len = 0;
		return m;
	}

	if ((m.len = read(sock,m.buff,m.alloc)) <= 0) {
		dbgprintf(0, "Read Failed: %s\n", strerror(errno));
		free(m.buff);
		m.buff = NULL;
		m.len = 0;
		return m;
	}

	return m;
}

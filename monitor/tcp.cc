/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 *****************************************************************************/
#include "monitor.h"
#include "tracker.h"
#include "tcp.h"
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <time.h>
using namespace std;

static const char* const state_strings[] = {"STATE_UNKNOWN", "STATE_INIT", "STATE_SLOW_START", 
						"STATE_CONG_AVOID", "STATE_FAST_RECOV", "STATE_RTO", "STATE_END"};


/* Handle Sequence Wrap */
/*static int seq_before(uint32_t s1, uint32_t s2)
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
			!(tcph->th_flags & TH_FIN) &&
			!(tcph->th_flags & TH_RST) &&
			tcph->th_off*4 == hdr.len;
}*/


TCP::TCP()
{
	this->thread_running = false;
	this->thread_cleanup = false;
	this->running = false;
	this->tcp_data_pkts = 0;
	this->tcp_data_low = 0;
	this->tcp_data_high = 0;
	this->tcp_ack_pkts = 0;
	this->tcp_ack_low = 0;
	this->tcp_ack_high = 0;
	this->tcp_port1 = 0;
	this->tcp_port2 = 0;
	this->state = STATE_INIT;
	pthread_rwlock_init(&lock, NULL);
}

TCP::~TCP()
{
	pthread_rwlock_destroy(&lock);
}

void TCP::new_packet(pkt_info pk, Message hdr)
{
	struct tcphdr *tcph;

	/* Sanity checks */
	if (hdr.len < (int)sizeof(tcphdr)) {
		return;
	}
	tcph = (struct tcphdr*)hdr.buff;
	if (tcph->th_off*4 > hdr.len) {
		return;
	}


	pthread_rwlock_rdlock(&lock);

	if (tcp_port1 == 0 && tcp_port2 == 0) {
		pthread_rwlock_wrlock(&lock);
		if (tcph->th_flags & TH_SYN) {
			tcp_port1 = ntohs(tcph->th_sport);
			tcp_port2 = ntohs(tcph->th_dport);
			dbgprintf(1, "Connection: src: %i, dst: %i\n", tcp_port1, tcp_port2);
		} else {
			dbgprintf(1, "Skipping packet from unknown connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
			goto out;
		}
	}

	if ((tcp_port1 != ntohs(tcph->th_sport) || tcp_port2 != ntohs(tcph->th_dport)) &&
	    (tcp_port2 != ntohs(tcph->th_sport) || tcp_port1 != ntohs(tcph->th_dport)) ) {
		dbgprintf(1, "Skipping packet from other connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
		goto out;
	}

	updateClassicCongestionControl(pk,hdr);

out:
	pthread_rwlock_unlock(&lock);
	return;
}

void TCP::updateClassicCongestionControl(pkt_info pk, Message hdr)
{
	struct tcphdr *tcph;

	/* Sanity checks */
	if (hdr.len < (int)sizeof(tcphdr)) {
		return;
	}
	tcph = (struct tcphdr*)hdr.buff;
	if (tcph->th_off*4 > hdr.len) {
		return;
	}

	/* Set State INIT on SYN */
	if (tcph->th_flags & TH_SYN) {
		state = STATE_INIT;
		return;
	}

	/* Set State END on FIN/RST */
	if ((tcph->th_flags & TH_FIN) ||
	    (tcph->th_flags & TH_RST)) {
		state = STATE_END;
		return;
	}

	/* Sanity */
	if (!(tcph->th_flags & TH_ACK)) {
		return;
	}

	/* Is data bearing packet */
	if (hdr.len > tcph->th_off*4) {
		tcp_data_pkts++;
		//tcp_data_bytes += (hdr.len - tcph->th_off*4);
	} else {
		tcp_ack_pkts++;
	}

	if (pk.msg.buff == NULL) {

	}
	return;
}

void TCP::processClassicCongestionControl() 
{
	if (state == STATE_INIT) {
		printState(old_state, state);
		old_state = state;	
	}

	if (state == STATE_END) {
		printState(old_state, state);
		old_state = state;
		return;
	}

	if (tcp_data_pkts == 0 && tcp_ack_pkts == 0) {
		idle_periods++;
	}

	if (NAGLE) {
		if (tcp_ack_pkts > tcp_data_pkts) {
			old_state = state;
			state = STATE_FAST_RECOV;
			printState(old_state, state);
		} else if (tcp_ack_pkts == 0 && tcp_data_pkts > 0) {
			old_state = state;
			state = STATE_RTO;
			printState(old_state, state);
		} else if (tcp_ack_pkts > 0.8*tcp_data_pkts) {
			old_state = state;
			state = STATE_SLOW_START;
			printState(old_state, state);
		} else if (tcp_ack_pkts > 0.3*tcp_data_pkts) {
			old_state = state;
			state = STATE_CONG_AVOID;
			printState(old_state, state);
		} else {
			old_state = state;
			state = STATE_UNKNOWN;
			printState(old_state, state);
		}
	} else {
		if (tcp_ack_pkts > 2.5*tcp_data_pkts) {
			old_state = state;
			state = STATE_FAST_RECOV;
			printState(old_state, state);
		} else if (tcp_ack_pkts == 0 && tcp_data_pkts > 0) {
			old_state = state;
			state = STATE_RTO;
			printState(old_state, state);
		} else if (tcp_ack_pkts > 1.5*tcp_data_pkts) {
			old_state = state;
			state = STATE_SLOW_START;
			printState(old_state, state);
		} else if (tcp_ack_pkts > 0.5*tcp_data_pkts) {
			old_state = state;
			state = STATE_CONG_AVOID;
			printState(old_state, state);
		} else {
			old_state = state;
			state = STATE_UNKNOWN;
			printState(old_state, state);
		}
	}
}

void TCP::printState(int oldstate, int state)
{
	struct timeval tmnow;
    struct tm *tm;
    char buf[30], usec_buf[6];

	if (oldstate == state) {
		return;
	}

    gettimeofday(&tmnow, NULL);
    tm = localtime(&tmnow.tv_sec);
    strftime(buf,30,"%Y-%m-%d-%H:%M:%S", tm);
    sprintf(usec_buf,"%06lu",(unsigned long)tmnow.tv_usec);

	dbgprintf(0, "[%s.%s] state = %s", buf,usec_buf, state_strings[state]);
}

/* Stupid pthreads/C++ glue*/
void* TCP::thread_run(void* arg)
{
	TCP *t = (TCP*)arg;
	t->run();
	t->thread_running = false;
	return NULL;
}

void TCP::run()
{
	struct timespec sl;
	struct timespec rem;

	while (running) {
		pthread_rwlock_wrlock(&lock);
		processClassicCongestionControl();
		pthread_rwlock_unlock(&lock);

		/* Sleep for interval */
		sl.tv_sec = 0;
		sl.tv_nsec = INTERVAL*1000000;
		while (nanosleep(&sl, &rem) < 0) {
			sl.tv_sec = rem.tv_sec;
			sl.tv_nsec = rem.tv_nsec;
		}
	}
}

bool TCP::start()
{
	running = true;
	if (pthread_create(&thread, NULL, thread_run, this) < 0) {
		dbgprintf(0, "Error: Failed to start tracker thread!: %s\n", strerror(errno));
		running = false;
		return false;
	}
	thread_running = true;
	thread_cleanup = true;
	return true;
}

bool TCP::stop()
{
	if (running) {
		running = false;
	}

	if (thread_cleanup) {
		thread_cleanup = false;
		pthread_join(thread, NULL);
	}
	return true;
}

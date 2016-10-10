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

struct timeval holding1;
struct timeval holding2;

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
	struct sigevent se;

	this->thread_running = false;
	this->thread_cleanup = false;
	this->running = false;
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
	this->state = STATE_INIT;
	this->urgent_event = false;
	this->prior_ratio = 0;
	pthread_rwlock_init(&lock, NULL);
	gettimeofday(&last_packet, NULL);
	pthread_mutex_init(&time_lock, NULL);
	memset(&se, 0, sizeof(struct sigevent));
	se.sigev_notify = SIGEV_SIGNAL;
	se.sigev_signo = SIGALRM;
	se.sigev_value.sival_int = 1;
	timer_create(CLOCK_REALTIME, &se, &pkt_timr);
	se.sigev_value.sival_int = 2;
	timer_create(CLOCK_REALTIME, &se, &int_timr);
}

TCP::~TCP()
{
	pthread_rwlock_destroy(&lock);
	pthread_mutex_destroy(&time_lock);
	timer_delete(pkt_timr);
	timer_delete(int_timr);
}

void TCP::new_packet(pkt_info pk, Message hdr)
{
	struct tcphdr *tcph;
	struct timeval tm;
	struct timeval diff;
	struct itimerspec tmr_set;

	/* Sanity checks */
	if (pk.msg.buff == NULL) {
		return;
	}
	if (hdr.len < (int)sizeof(tcphdr)) {
		return;
	}
	tcph = (struct tcphdr*)hdr.buff;
	if (tcph->th_off*4 > hdr.len) {
		return;
	}


	pthread_rwlock_rdlock(&lock);

	if (tcp1_port == 0 && tcp2_port == 0) {
		if (tcph->th_flags & TH_SYN) {
			pthread_rwlock_unlock(&lock);
			pthread_rwlock_wrlock(&lock);
			tcp1_port = ntohs(tcph->th_sport);
			tcp2_port = ntohs(tcph->th_dport);
			dbgprintf(1, "Connection: src: %i, dst: %i\n", tcp1_port, tcp2_port);
		} else {
			dbgprintf(1, "Skipping packet from unknown connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
			goto out;
		}
	}

	if ((tcp1_port != ntohs(tcph->th_sport) || tcp2_port != ntohs(tcph->th_dport)) &&
	    (tcp2_port != ntohs(tcph->th_sport) || tcp1_port != ntohs(tcph->th_dport)) ) {
		dbgprintf(1, "Skipping packet from other connection... src: %u, dst:%u\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
		goto out;
	}

	if (pthread_mutex_trylock(&time_lock) == 0) {
		gettimeofday(&tm, NULL);
		timersub(&tm,&last_packet,&diff);
		if (diff.tv_sec > 0 || diff.tv_usec > INT_PKT*MSEC2USEC) {
			memcpy(&last_idle, &tm, sizeof(struct timeval));
		} 
		memcpy(&last_packet, &tm, sizeof(struct timeval));
		tmr_set.it_value.tv_sec = 0;
		tmr_set.it_value.tv_nsec = INT_PKT*MSEC2NSEC;
		tmr_set.it_interval.tv_sec = 0;
		tmr_set.it_interval.tv_nsec = 0;
		timer_settime(pkt_timr,0,&tmr_set,NULL);
		pthread_mutex_unlock(&time_lock);
	}

	updateClassicCongestionControl(hdr);

out:
	pthread_rwlock_unlock(&lock);
	return;
}

void TCP::triggerTimerNow()
{
	struct itimerspec tmr_set;

	pthread_mutex_lock(&time_lock);
	urgent_event = true;
	tmr_set.it_value.tv_sec = 0;
	tmr_set.it_value.tv_nsec = 1;
	tmr_set.it_interval.tv_sec = 0;
	tmr_set.it_interval.tv_nsec = 0;
	timer_settime(pkt_timr,0,&tmr_set,NULL);
	pthread_mutex_unlock(&time_lock);
}

void TCP::updateClassicCongestionControl(Message hdr)
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
		triggerTimerNow();
		return;
	}

	/* Set State END on FIN/RST */
	if ((tcph->th_flags & TH_FIN) ||
	    (tcph->th_flags & TH_RST)) {
		state = STATE_END;
		triggerTimerNow();
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
				triggerTimerNow();
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
				triggerTimerNow();
				tcp_retransmits++;
			}
	}
	return;
}

void TCP::processClassicCongestionControl() 
{
	double cur = 0;

	/* Don't do anything before connection is established */
	if (tcp1_port == 0 || tcp2_port == 0) {
		return;
	}

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
		return;
	}

	/* Compute ack/data ratios */
	if (tcp_ack_bytes > 0) {
		cur = tcp_data_bytes / (tcp_ack_bytes*1.0);
	}
	if (prior_ratio == 0) {
		prior_ratio = cur;
	}

	/* Determine state */
	if (tcp_ack_pkts == 0 && tcp_data_pkts > 0 && tcp_data_pkts < 10 && idle_periods > 3) {
		old_state = state;
		state = STATE_RTO;
		printState(old_state, state);
	} else if (state == STATE_FAST_RECOV && 
				tcp1_ack_high <= tcp1_ack_hold && 
				tcp2_ack_high <= tcp2_ack_hold) {
		old_state = state;
		state = STATE_FAST_RECOV;
		printState(old_state, state);
	//} else if (cur < 0.8 && tcp_retransmits > 0) {
	} else if (tcp_retransmits > 0) {
		if (state != STATE_FAST_RECOV) {
			tcp1_ack_hold = tcp2_seq_high + 1;
			tcp2_ack_hold = tcp1_seq_high + 1;
		}
		old_state = state;
		state = STATE_FAST_RECOV;
		printState(old_state, state);
	//} else if (tcp_data_bytes > 1.8*tcp_ack_bytes) {
	} else if ((cur+prior_ratio)/2 > 1.8) {
		old_state = state;
		state = STATE_SLOW_START;
		printState(old_state, state);
	//} else if (tcp_data_bytes > 0.8*tcp_ack_bytes) {
	} else if ((cur+prior_ratio)/2 > 0.8) {
		old_state = state;
		state = STATE_CONG_AVOID;
		printState(old_state, state);
	} else {
		//dbgprintf(0, "Cur: %e, Last: %e\n", cur, prior_ratio);
		if (cur != 0) {
			prior_ratio = (cur + prior_ratio)/2;
		}
		return;
	}
	
	prior_ratio = cur;
	tcp_ack_pkts = 0;
	tcp_ack_bytes = 0;
	tcp_ack_dup = 0;
	tcp_data_pkts = 0;
	tcp_data_bytes = 0;
	tcp_retransmits = 0;
	idle_periods = 0;
	return;
}

char* TCP::timestamp(char* buff, int len) {
	struct timeval tmnow;
	struct tm *tm;
	int ret;
	char usec_buff[10];
    
	gettimeofday(&tmnow, NULL);
    tm = localtime(&tmnow.tv_sec);
    ret = strftime(buff,len,"%Y-%m-%d-%H:%M:%S", tm);
	if (ret == 0) {
		memset(buff, 0, len);
		return NULL;
	}
	len -= ret;
	strncat(buff,".", len);
	len--;
    snprintf(usec_buff,10,"%06lu",(unsigned long)tmnow.tv_usec);
	strncat(buff, usec_buff, len);
	return buff;
}

void TCP::printState(int oldstate, int state)
{
    char buf[40];

	if (oldstate == state) {
		return;
	}
	dbgprintf(0, "[%s] state = %s, lp=%lu.%06lu, il=%lu.%06lu\n", timestamp(buf,40), state_strings[state], holding1.tv_sec, holding1.tv_usec, holding2.tv_sec, holding2.tv_usec);
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
	struct timeval tm;
	struct timeval diff_pkt;
	struct timeval diff_idle;
	sigset_t sigset;
	int sig;
    int error;

	/* Allow SIGALRM */
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

	while (running) {
		error = sigwait(&sigset, &sig);
        if (error != 0) {
			dbgprintf(0, "Error: sigwait() failed!\n");
			break;
		}

		pthread_mutex_lock(&time_lock);
		gettimeofday(&tm, NULL);
		timersub(&tm,&last_packet,&diff_pkt);
		timersub(&tm,&last_idle,&diff_idle);
		pthread_mutex_unlock(&time_lock);
		memcpy(&holding1,&diff_pkt,sizeof(struct timeval));
		memcpy(&holding2,&diff_idle,sizeof(struct timeval));

		if ((diff_idle.tv_sec > 0 || diff_idle.tv_usec >= 4*INT_TME*MSEC2USEC) ||
			(diff_pkt.tv_sec > 0 || diff_pkt.tv_usec >= INT_PKT*MSEC2USEC) || urgent_event) {
			pthread_rwlock_wrlock(&lock);
			processClassicCongestionControl();
			urgent_event = false;
			pthread_rwlock_unlock(&lock);
		}
	}
}

bool TCP::start()
{
	struct itimerspec tmr_set;

	running = true;
	if (pthread_create(&thread, NULL, thread_run, this) < 0) {
		dbgprintf(0, "Error: Failed to start tracker thread!: %s\n", strerror(errno));
		running = false;
		return false;
	}
	thread_running = true;
	thread_cleanup = true;

	pthread_mutex_lock(&time_lock);
	tmr_set.it_value.tv_sec = 0;
	tmr_set.it_value.tv_nsec = INT_TME*MSEC2NSEC;
	tmr_set.it_interval.tv_sec = 0;
	tmr_set.it_interval.tv_nsec = INT_TME*MSEC2NSEC;
	timer_settime(int_timr,0,&tmr_set,NULL);
	pthread_mutex_unlock(&time_lock);
	return true;
}

bool TCP::stop()
{
	struct itimerspec tmr_set;

	if (running) {
		running = false;
		pthread_mutex_lock(&time_lock);
		tmr_set.it_value.tv_sec = 0;
		tmr_set.it_value.tv_nsec = INT_PKT*MSEC2NSEC;
		tmr_set.it_interval.tv_sec = 0;
		tmr_set.it_interval.tv_nsec = 0;
		timer_settime(int_timr,0,&tmr_set,NULL);
		pthread_mutex_unlock(&time_lock);
	}

	if (thread_cleanup) {
		thread_cleanup = false;
		pthread_join(thread, NULL);
	}
	return true;
}



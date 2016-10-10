/******************************************************************************
 * Author: Samuel Jero <sjero@purdue.edu>
 * Congestion Control Sender Monitor: Classic AIMD, loss-based CC algorithm
 *****************************************************************************/
#include "monitor.h"
#include "tracker.h"
#include "classic.h"
#include <sys/time.h>
#include <time.h>
using namespace std;

static const char* const state_strings[] = {"STATE_UNKNOWN", "STATE_INIT", "STATE_SLOW_START", 
						"STATE_CONG_AVOID", "STATE_FAST_RECOV", "STATE_RTO", "STATE_END"};

struct timeval holding1;
struct timeval holding2;

Classic::Classic(Proto *p)
{
	struct sigevent se;

	this->p = p;
	this->thread_running = false;
	this->thread_cleanup = false;
	this->running = false;
	this->state = STATE_INIT;
	this->urgent_event = false;
	this->prior_ratio = 0;
	gettimeofday(&last_packet, NULL);
	pthread_mutex_init(&time_lock, NULL);
	
	/* Create timers */
	memset(&se, 0, sizeof(struct sigevent));
	se.sigev_notify = SIGEV_SIGNAL;
	se.sigev_signo = SIGALRM;
	se.sigev_value.sival_int = 1;
	timer_create(CLOCK_REALTIME, &se, &pkt_timr);
	se.sigev_value.sival_int = 2;
	timer_create(CLOCK_REALTIME, &se, &int_timr);
}

Classic::~Classic()
{
	pthread_mutex_destroy(&time_lock);
	timer_delete(pkt_timr);
	timer_delete(int_timr);
}

void Classic::new_packet(pkt_info pk, Message hdr)
{
	struct timeval tm;
	struct timeval diff;
	struct itimerspec tmr_set;

	if (!p->new_packet(pk,hdr)) {
		return;
	}

	/* Record packet time as last_packet */
	if (pthread_mutex_trylock(&time_lock) == 0) {
		gettimeofday(&tm, NULL);
		timersub(&tm,&last_packet,&diff);

		/* And Possibly last_idle*/
		if (diff.tv_sec > 0 || diff.tv_usec > INT_PKT*MSEC2USEC) {
			memcpy(&last_idle, &tm, sizeof(struct timeval));
		} 
		memcpy(&last_packet, &tm, sizeof(struct timeval));

		/* Reset packet timer */
		tmr_set.it_value.tv_sec = 0;
		tmr_set.it_value.tv_nsec = INT_PKT*MSEC2NSEC;
		tmr_set.it_interval.tv_sec = 0;
		tmr_set.it_interval.tv_nsec = 0;
		timer_settime(pkt_timr,0,&tmr_set,NULL);
		pthread_mutex_unlock(&time_lock);
	}

	if (p->isStart() || p->isEnd() || p->Retransmissions() > 0) {
		triggerTimerNow();
	}

	return;
}

void Classic::triggerTimerNow()
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

void Classic::processClassicCongestionControl() 
{
	double cur = 0;

	/* Don't do anything before connection is established */
	if (p->isUnknown()) {
		return;
	}

	if (p->isStart()) {
		state = STATE_INIT;
		printState(old_state, state);
		old_state = state;
	}

	if (p->isEnd()) {
		state = STATE_END;
		printState(old_state, state);
		old_state = state;
		return;
	}

	if (p->DataPkts() == 0 && p->AckPkts() == 0) {
		idle_periods++;
		return;
	}

	/* Compute ack/data ratios */
	if (p->AckBytes() > 0) {
		cur = p->DataBytes() / (p->AckBytes()*1.0);
	}
	if (prior_ratio == 0) {
		prior_ratio = cur;
	}

	/* Determine state */
	if (p->AckPkts() == 0 && p->DataPkts() > 0 && p->DataPkts() < 10 && idle_periods > 3) {
		old_state = state;
		state = STATE_RTO;
		printState(old_state, state);
	} else if (state == STATE_FAST_RECOV && !p->areAckHoldsPassed()) {
		old_state = state;
		state = STATE_FAST_RECOV;
		printState(old_state, state);
	//} else if (cur < 0.8 && p->Retransmissions() > 0) {
	} else if (p->Retransmissions() > 0) {
		if (state != STATE_FAST_RECOV) {
			p->setAckHolds();
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
	p->resetCtrs();
	idle_periods = 0;
	return;
}

char* Classic::timestamp(char* buff, int len) {
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

void Classic::printState(int oldstate, int state)
{
    char buf[40];

	if (oldstate == state) {
		return;
	}

	Tracker::get().sendState(state_strings[state], p->getIP1(), p->getIP2(), p->name());
	dbgprintf(1, "[%s] state = %s, lp=%lu.%06lu, il=%lu.%06lu\n", timestamp(buf,40), state_strings[state], holding1.tv_sec, holding1.tv_usec, holding2.tv_sec, holding2.tv_usec);
}

/* Stupid pthreads/C++ glue*/
void* Classic::thread_run(void* arg)
{
	Classic *t = (Classic*)arg;
	t->run();
	t->thread_running = false;
	return NULL;
}

void Classic::run()
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
			p->lockCtrs();
			processClassicCongestionControl();
			urgent_event = false;
			p->unlockCtrs();
		}
	}
}

bool Classic::start()
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

bool Classic::stop()
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



/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu>
* TCP Congestion Control Proxy: Malicious Processing
******************************************************************************/
#ifndef _ATTACKER_H
#define _ATTACKER_H
#include "proxy.h"
#include "args.h"
#include <map>
#include <list>
#include <vector>
#include <string>

#define ACTION_ID_ERR			(-1)
#define ACTION_ID_MIN			0
#define ACTION_ID_MAX			10



class Attacker{
	private:
		Attacker();

	public:
		~Attacker();
		static Attacker& get();
		bool addCommand(Message m, Message *resp);
		pkt_info doAttack(pkt_info pk);
		bool start();
		bool stop();

	private:
		int normalize_action_type(char *s);
		void print(pkt_info pk);
		
		pthread_rwlock_t lock;
};


#endif

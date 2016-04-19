/******************************************************************************
* Author: Samuel Jero <sjero@purdue.edu> and Xiangyu Bu <xb@purdue.edu>
* TCP Congestion Control Proxy: Malicious Processing
******************************************************************************/
#include "attacker.h"
#include "csv.h"
#include "args.h"
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
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

	//pk = applyActions(pk, it4);

	pthread_rwlock_unlock(&lock);
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

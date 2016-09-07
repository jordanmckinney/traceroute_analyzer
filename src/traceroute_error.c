#define MAX_STR_LEN 20

#include <arpa/inet.h>
#include <pcap.h>
#include "../include/traceroute.h"
#include "../include/traceroute_time.h"

void problem_pkt(struct timeval ts, const char *reason){
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr){
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
}

#define MAX_STR_LEN 20

#include <pcap.h>
#include <netinet/ip_icmp.h>
#include "../include/structs.h"

double get_time(struct timeval ts){
	// multiply int part so that least significant
	// fig is greater than most significant of 
	// dec part, then add them and divide to get ms
	long int_part = 1000000*((int)ts.tv_sec);
	long dec_part = (int)ts.tv_usec;
	return (double)(int_part+dec_part)/1000;
}

const char *timestamp_string(struct timeval ts){
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}
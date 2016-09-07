#ifndef TRACEROUTE_HELPERS
#define TRACEROUTE_HELPERS

// returns standard deviation
double get_sd(double data[], int n);

// returns average of doubles
double get_avg(double data[], int n);

// returns IP protocol code name given code number 
// only supports ICMP and UDP
const char *get_protocol_name(int code);

#endif
#ifndef TRACEROUTE_TIME
#define TRACEROUTE_TIME

// takes timeval struct and returns time as a double in millisec
double get_time(struct timeval ts);

// returns timestamp string
const char *timestamp_string(struct timeval ts);

#endif
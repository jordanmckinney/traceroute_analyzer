#ifndef TRACEROUTE_ERROR
#define TRACEROUTE_ERROR

// prints error message for invalid packet
void problem_pkt(struct timeval ts, const char *reason);

// prints error message for too short packet
void too_short(struct timeval ts, const char *truncated_hdr);

#endif
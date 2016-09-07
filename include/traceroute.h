#ifndef TRACEROUTE
#define TRACEROUTE

#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "structs.h"

// performs error checks and sorts packets into potential probes or potential replies
void sort_packet(const unsigned char *packet, struct pcap_pkthdr header, probe_summary **root_ptr);

// sorts probe into probe summary objects, adds fragments
void sort_probe(const unsigned char *packet,unsigned int capture_len, struct ip *ip, struct timeval ts, probe_summary **root_ptr, int *curr_ttl_ptr);

// creates probe summary object
probe_summary *set_probe(const unsigned char *packet, struct ip *ip, struct timeval ts, int *curr_ttl_ptr);

// adds datagram fragment to probe summary object
void add_fragment(struct ip *ip, struct timeval ts, probe_summary *curr_summ);

// sorts reply to correct probe
void sort_reply(const unsigned char *packet, unsigned int capture_len, struct ip *ip, struct timeval ts, probe_summary **root_ptr);

// checks if echo datagram is destination reached 
void sort_echo(struct ip *ip,struct icmp *icmp, struct timeval ts, probe_summary **root_ptr);

#endif
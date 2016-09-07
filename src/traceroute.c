#define MAX_STR_LEN 20
#define MIN_IP_HDR_LEN 20
#define MAX_FRAGS_PER_HOP 60
#define UDP_ICMP_HEADER_SIZE 8

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQST 8
#define ICMP_TYPE_TTL_EXC 11
#define ICMP_TYPE_DST_UNRCH 3
#define ICMP_CODE_ZERO 0
#define ICMP_CODE_PRT_UNRCH 3

#define IP_FRAG_OFFSET 0x1FFF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../include/structs.h"
#include "../include/traceroute.h"
#include "../include/traceroute_error.h"
#include "../include/traceroute_print.h"
#include "../include/traceroute_time.h"

int main(int argc, char *argv[]){
	++argv; --argc;
	
	if (argc != 1){
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL){
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}
	probe_summary *root = 0;
	probe_summary **root_ptr = &root;
	struct pcap_pkthdr header;
	const unsigned char *packet;

	// send all packets to be sorted
	while ((packet = pcap_next(pcap, &header)) != NULL){
		sort_packet(packet, header, root_ptr);
	}
	// uncomment line below to print all probe summary objects
	// print_probes(root); 
	print_summary(root);
	return 0;
}

void sort_packet(const unsigned char *packet, struct pcap_pkthdr header, probe_summary **root_ptr){
	struct timeval ts = header.ts;
	unsigned int capture_len = header.caplen;
	if (capture_len < sizeof(struct ether_header)){
		too_short(ts, "Ethernet header");
		return;
	}
	// skip over ethernet header
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	if (capture_len < sizeof(struct ip)){ 
		too_short(ts, "IP header");
		return;
	}
	struct ip *ip;
	ip = (struct ip*) packet;
	unsigned int IP_hdr_len;
	IP_hdr_len = ip->ip_hl*4;
	if (capture_len < IP_hdr_len){ 
		too_short(ts, "IP header with options");
		return;
	}

	// only 2 protocols are supported
	u_char ip_proto=ip->ip_p;
	if(ip_proto!=IPPROTO_ICMP&&ip_proto!=IPPROTO_UDP) 
		return;
	
	// if packet is probe or fragment of probe then ttl value must be in sequence
	static int curr_ttl=1;
	int * curr_ttl_ptr= &curr_ttl;
	int valid_ttl=0;
	if(ip->ip_ttl==curr_ttl||ip->ip_ttl==curr_ttl+1) valid_ttl=1;

	packet += IP_hdr_len;
	capture_len -= IP_hdr_len;

	// packet is potential probe
	if(valid_ttl){
		sort_probe(packet,capture_len,ip,ts,root_ptr,curr_ttl_ptr);
	}
	// packet is potential reply 
	if(ip_proto==IPPROTO_ICMP){
		sort_reply(packet,capture_len,ip,ts,root_ptr);
	}
}

void sort_probe(const unsigned char *packet, unsigned int capture_len, struct ip *ip, struct timeval ts, probe_summary **root_ptr, int *curr_ttl_ptr){
	// set root, ensure root is set
	if(*root_ptr==NULL && ip->ip_ttl==1){
		*root_ptr=set_probe(packet,ip,ts,curr_ttl_ptr);
		return;
	}
	if(*root_ptr==NULL) return;

	// check if probe is fragment of another 
	// if ids match and 'more fragments' flag == 1 then match
	probe_summary *prev, *curr;
	for(curr=*root_ptr; curr!=NULL; prev=curr, curr=curr->next){
		if(ntohs(ip->ip_id)==curr->probe_id && curr->curr_m_flag==1){
			add_fragment(ip,ts,curr);
			return;
		}
	}
	// set as new probe
	prev->next=set_probe(packet,ip,ts,curr_ttl_ptr);
}

probe_summary *set_probe(const unsigned char *packet, struct ip *ip, struct timeval ts, int *curr_ttl_ptr){
	probe_summary *probe_summ = (probe_summary*)malloc(sizeof(probe_summary));
	u_char ip_proto=ip->ip_p;

	if(ip_proto==IPPROTO_ICMP){
		struct icmp *icmp = (struct icmp*) packet;
		// probes must have the following type and code
		if(icmp->icmp_type!=ICMP_TYPE_ECHO_REQST||icmp->icmp_code!=ICMP_CODE_ZERO) 
			return NULL;
		probe_summ->icmp_idnum = icmp->icmp_id;
		probe_summ->icmp_seqnum = icmp->icmp_seq;
	}
	else if(ip_proto==IPPROTO_UDP){
		struct udphdr *udp = (struct udphdr*) packet;
		probe_summ->port_src = ntohs(udp->uh_sport);
		probe_summ->port_dst = ntohs(udp->uh_dport);
	}

	// set remaining data fields in probe summary object
	strcpy(probe_summ->ip_src,inet_ntoa(ip->ip_src));
	strcpy(probe_summ->ip_dst,inet_ntoa(ip->ip_dst));
	probe_summ->ttl_num = ip->ip_ttl;
	probe_summ->probe_id = ntohs(ip->ip_id);
	probe_summ->probe_proto=ip_proto;	
	probe_summ->curr_m_flag = (int)(ntohs(ip->ip_off) & IP_MF)>>13;
	probe_summ->fragment_count=1;

	// set packet specifics in probe packet object
	probe_packet *probe_pack = (probe_packet*)malloc(sizeof(probe_packet));
	probe_pack->probe_time = get_time(ts);
	
	probe_summ->first_packet = probe_pack;
	*curr_ttl_ptr = ip->ip_ttl;

	return probe_summ;
}

void add_fragment(struct ip *ip, struct timeval ts, probe_summary *curr_summ){
	u_char ip_proto=ip->ip_p;
	curr_summ->curr_m_flag = (int)(ntohs(ip->ip_off) & IP_MF)>>13;
	curr_summ->fragment_count++;

	probe_packet *probe_pack = (probe_packet*)malloc(sizeof(probe_packet));
	probe_pack->probe_time = get_time(ts);
	probe_pack->frag_offset = 8*(int)(ntohs(ip->ip_off)&IP_FRAG_OFFSET);
	
	// go to end of probe packet list, then add
	probe_packet *curr_pack = curr_summ->first_packet;
	while(curr_pack->next_pack!=NULL) curr_pack = curr_pack->next_pack;
	
	curr_pack->next_pack = probe_pack;
}

void sort_reply(const unsigned char *packet, unsigned int capture_len, struct ip *ip, struct timeval ts, probe_summary **root_ptr){
	struct icmp *icmp = (struct icmp*) packet;
	
	// may be final destination reply (windows)
	if(icmp->icmp_type==ICMP_CODE_ZERO&&icmp->icmp_code==ICMP_CODE_ZERO)
		sort_echo(ip,icmp,ts,root_ptr);
	
	// check if destination reached (linux)
	int final_reply=0;
	if(icmp->icmp_type==ICMP_TYPE_DST_UNRCH&&icmp->icmp_code==ICMP_CODE_PRT_UNRCH)
		final_reply=1;

	// check if normal reply
	int valid_reply=0;
	if(icmp->icmp_type==ICMP_TYPE_TTL_EXC&&icmp->icmp_code==ICMP_CODE_ZERO) 
		valid_reply=1;

	if(!valid_reply&&!final_reply) return;

	packet+=UDP_ICMP_HEADER_SIZE;
	capture_len-=UDP_ICMP_HEADER_SIZE;

	if (capture_len < MIN_IP_HDR_LEN) return;
	struct ip *inner_ip = (struct ip*) packet;
	
	packet+=inner_ip->ip_hl*4;
	capture_len-=inner_ip->ip_hl*4;
	if (capture_len < UDP_ICMP_HEADER_SIZE) return;

	uint16_t port_src=0, port_dst=0; 	
	uint16_t icmp_idnum=0, icmp_seqnum=0;
	if(inner_ip->ip_p==IPPROTO_UDP){
		struct udphdr *inner_udp = (struct udphdr*) packet;
		port_src = ntohs(inner_udp->uh_sport);
		port_dst = ntohs(inner_udp->uh_dport);
	}
	else if(inner_ip->ip_p==IPPROTO_ICMP){
		struct icmp *inner_icmp = (struct icmp*) packet;
		icmp_idnum = inner_icmp->icmp_id;
		icmp_seqnum = inner_icmp->icmp_seq;
	}

	int ip_match = 0, port_match = 0, id_seq_match = 0;

	// go through all probe summary objects, see if reply matches
	probe_summary *curr;
	for(curr=*root_ptr; curr!=NULL; curr=curr->next){
		if(strcmp(inet_ntoa(inner_ip->ip_src),curr->ip_src)==0 && 
				strcmp(inet_ntoa(inner_ip->ip_dst),curr->ip_dst)==0) 
			ip_match = 1;
		if(port_src==curr->port_src && port_dst==curr->port_dst) 
			port_match = 1;
		if(icmp_idnum==curr->icmp_idnum && icmp_seqnum==curr->icmp_seqnum)
			id_seq_match = 1;
		
		if(ip_match&&port_match&&id_seq_match){
			strcpy(curr->intermediate_ip,inet_ntoa(ip->ip_src));
			curr->dest_reached=final_reply;
			curr->reply_proto=ip->ip_p;
			curr->reply_time = get_time(ts);
			return;
		}
	}
}

void sort_echo(struct ip *ip,struct icmp *icmp, struct timeval ts, probe_summary **root_ptr){
	uint16_t icmp_idnum=icmp->icmp_id;
	uint16_t icmp_seqnum=icmp->icmp_seq;

	int ultimate_ip_match=0, id_seq_match=0;
	probe_summary *curr;
	for(curr=*root_ptr; curr!=NULL; curr=curr->next){
		
		// if response came from ultimate dest, then dest reached
		if(strcmp(inet_ntoa(ip->ip_src),curr->ip_dst)==0) 
			ultimate_ip_match = 1;
		if(icmp_idnum==curr->icmp_idnum && icmp_seqnum==curr->icmp_seqnum)
			id_seq_match = 1;
		
		if(ultimate_ip_match&&id_seq_match){
			curr->dest_reached=1;
			curr->reply_proto=ip->ip_p;
			curr->reply_time=get_time(ts);
			strcpy(curr->intermediate_ip,inet_ntoa(ip->ip_src));
			return;
		}
	}
}
#ifndef STRUCTS_H
#define STRUCTS_H

#define MAX_PROBES_PER_TTL 50

typedef struct probe_summary {
	char ip_src[MAX_STR_LEN];	 		
	char ip_dst[MAX_STR_LEN]; 			
	char intermediate_ip[MAX_STR_LEN]; 	
	uint16_t port_src; 					
	uint16_t port_dst; 					
	uint16_t icmp_idnum;
	uint16_t icmp_seqnum;
	u_char ttl_num;
	u_char probe_proto;
	u_char reply_proto;
	uint16_t probe_id;
	int curr_m_flag;
	int fragment_count;
	int dest_reached;	// set to 1 if final destination reached
	double reply_time;
	double rtt_time;
	struct probe_packet *first_packet;
	struct probe_summary *next;
} probe_summary;

typedef struct probe_packet{
	double probe_time;
	double response_time;
	short frag_offset;
	struct probe_packet *next_pack;
} probe_packet;

typedef struct ttl_summary{
	struct ip_summary *first_ip;
	int ttl;
	int ip_count;
	struct ttl_summary *next_ttl;
} ttl_summary;

typedef struct ip_summary{
	char ip[MAX_STR_LEN]; 	
	int num_times;
	double times[MAX_PROBES_PER_TTL*2];
	struct ip_summary *next_ip;
} ip_summary;

#endif
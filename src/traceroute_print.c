#define MAX_STR_LEN 20
#define MAX_FRAGS_PER_HOP 60
#define MAX_PROBES_PER_TTL 50
#define MAX_HOPS 64
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../include/traceroute.h"
#include "../include/traceroute_helpers.h"
#include "../include/traceroute_print.h"

void print_summary(probe_summary *root){
	probe_summary *curr = root;
	while(curr->reply_time==0 &&curr->next!=NULL) curr=curr->next;

	printf("The IP address of the source node: %s\n", curr->ip_src);
	printf("The IP address of the ultimate destination: %s\n\n", curr->ip_dst);
	
	print_intermediate_routers(root);
	printf("\n");
	print_protocols(root);
	printf("\n\n");
	print_fragments(root);
	printf("\n");
	print_time_stats(root);
	printf("\n");
	print_num_rtts(root);
}

void print_intermediate_routers(probe_summary *root){
	printf("The IP addresses of the intermediate destination nodes:\n");
		
	char intermed_ips[MAX_PROBES_PER_TTL][MAX_STR_LEN];
	int current_router = 1;
	int responses=0;
	probe_summary *curr;
	for(curr=root; curr!=NULL&&curr->dest_reached!=1; curr=curr->next){
		
		int end_of_this_ttl=0;
		if(curr->next==NULL||curr->next->ttl_num==current_router+1||curr->next->dest_reached==1)
			end_of_this_ttl = 1;

		if(!end_of_this_ttl && curr->reply_time==0) 
			continue;

		// add first IP to list
		int i, add_ip=1;
		if(curr->reply_time!=0 && responses==0)
			strcpy(intermed_ips[responses++],curr->intermediate_ip);
		
		// add IP to list if not already in list
		if(curr->reply_time!=0){
			for(i=0;i<responses;i++){
				if(strcmp(intermed_ips[i],curr->intermediate_ip)==0){
					add_ip=0;
					break;
				}
			}
			if(add_ip) strcpy(intermed_ips[responses++],curr->intermediate_ip);
		}
				
		// no response for all probes of given ttl value
		if(end_of_this_ttl&&responses==0){
			printf("\trouter %d:\tNO REPLY\n", current_router);
			current_router++;
			responses=0;
			continue;
		}

		if(end_of_this_ttl){
			printf("\trouter %d:\t", current_router);
			int i;
			for(i=0;i<responses;i++)
				printf("%s, ", intermed_ips[i]);
			printf("\n");

			current_router++;
			responses=0;
		}
	}
}

void print_protocols(probe_summary *root){
	probe_summary *curr = root;

	// find probe that received response
	// all probes will have same probe protocol and response protocol
	for(curr=root;curr!=NULL&&curr->reply_time==0;curr=curr->next);
	if(curr==NULL) return;
	
	printf("The values in the protocol field of IP headers:\n");
	if(curr->probe_proto==curr->reply_proto){
		printf("\t%d: %s", curr->probe_proto, get_protocol_name(curr->probe_proto));
		return;
	}
	printf("\t%d: %s\n", curr->reply_proto, get_protocol_name(curr->reply_proto));
	printf("\t%d: %s", curr->probe_proto, get_protocol_name(curr->probe_proto));
}

void print_fragments(probe_summary *root){
	printf("TTL | Datagram ID | # Fragments | Offset of last fragment\n");
	printf("---------------------------------------------------------\n");

	probe_summary *curr_summ;
	probe_packet *curr_pack;
	int last_hop=MAX_HOPS;
	int no_fragments=1;
	for(curr_summ=root; curr_summ!=NULL; curr_summ=curr_summ->next){
		
		// no fragments to print
		if(curr_summ->fragment_count==1)continue;
		
		// do not print past final hop / dest reached
		if(curr_summ->ttl_num>last_hop) return;
		if(curr_summ->dest_reached==1) last_hop=curr_summ->ttl_num;
		curr_pack = curr_summ->first_packet;
		
		// go to final fragment
		while(curr_pack->next_pack!=NULL) curr_pack = curr_pack->next_pack;		
		printf(" %d\t\t%d\t\t\t%d\t\t\t\t%d\n", curr_summ->ttl_num,curr_summ->probe_id,curr_summ->fragment_count,
			curr_pack->frag_offset);
		no_fragments=0;
	}
	if(no_fragments)printf("\tNO FRAGMENTS\n");
}

void print_time_stats(probe_summary *root){
	printf("RTT Statistics:\n\n");

	ttl_summary *root_ttl = 0;
	ttl_summary **root_ttl_ptr = &root_ttl;
	
	set_summary_rtts(root);
	generate_ttl_data(root,root_ttl_ptr);
	
	// get source IP address
	probe_summary *curr_summ=root;
	while(curr_summ->reply_time==0&&curr_summ->next!=NULL) curr_summ=curr_summ->next;

	ttl_summary *ttl_summ;
	int current_router;
	for(ttl_summ=*root_ttl_ptr;ttl_summ!=NULL;ttl_summ=ttl_summ->next_ttl){
		current_router=ttl_summ->ttl;
		if(ttl_summ->ip_count==0){
			printf("%d:\tNO REPLY\n",current_router);
		}
		else{
			ip_summary *ip_summ;
			printf("%d:", ttl_summ->ttl);
			for(ip_summ=ttl_summ->first_ip;ip_summ!=NULL;ip_summ=ip_summ->next_ip){
				printf("\tThe avg RTT between %s and %s is %.2f ms, the s.d is: %.2f ms\n",
						curr_summ->ip_src,
						ip_summ->ip,
						get_avg(ip_summ->times,ip_summ->num_times),
						get_sd(ip_summ->times,ip_summ->num_times));		
			}
		}
	}
}

void generate_ttl_data(probe_summary *root, ttl_summary **root_ttl_ptr){
	probe_summary *curr_summ;
	int current_router=1;

	ttl_summary *ttl_summ;
	*root_ttl_ptr = (ttl_summary*)malloc(sizeof(ttl_summary));
	ttl_summ = *root_ttl_ptr;

	// iterate through all probe summary objects creating new ttl summary objects
	for(curr_summ=root; curr_summ!=NULL; curr_summ=curr_summ->next){
		if(ttl_summ->ttl==0) ttl_summ->ttl=current_router;

		if(curr_summ->reply_time!=0){
			ip_summary *ip_summ;

			if(ttl_summ->first_ip==NULL){
				ip_summ = (ip_summary*)malloc(sizeof(ip_summary));
				strcpy(ip_summ->ip,curr_summ->intermediate_ip);
				ip_summ->times[ip_summ->num_times++]=curr_summ->rtt_time;
				ttl_summ->first_ip=ip_summ;
				ttl_summ->ip_count=1;
			}
			// check against against existing ip summaries to see if same ip
			else{
				for(ip_summ=ttl_summ->first_ip;ip_summ!=NULL;ip_summ=ip_summ->next_ip){
					if(strcmp(curr_summ->intermediate_ip,ip_summ->ip)==0){
						ip_summ->times[ip_summ->num_times++]=curr_summ->rtt_time;
						break;
					}
					// did not match any, create new ip summary
					if(ip_summ->next_ip==NULL){
						ip_summary *ip_summ_temp = (ip_summary*)malloc(sizeof(ip_summary));
						strcpy(ip_summ_temp->ip,curr_summ->intermediate_ip);
						ip_summ_temp->times[ip_summ_temp->num_times++]=curr_summ->rtt_time;
						ip_summ->next_ip=ip_summ_temp;
						ttl_summ->ip_count++;
						break;
					}
				}
			}
		}
		// if next probe summary has greater ttl val or null
		if(curr_summ->next==NULL) return;
		if(curr_summ->next->ttl_num==current_router+1){
			if(curr_summ->dest_reached==1) return;
			ttl_summ->next_ttl = (ttl_summary*)malloc(sizeof(ttl_summary));
			ttl_summ = ttl_summ->next_ttl;
			current_router++;
		}
	}
}

void set_summary_rtts(probe_summary *root){
	probe_summary *curr_summ;
	for(curr_summ=root; curr_summ!=NULL; curr_summ=curr_summ->next){
		int count =1;
		double sum =0.0;
		probe_packet *curr_pack = curr_summ->first_packet;
		while(curr_pack!=NULL){
			sum+=(curr_summ->reply_time-curr_pack->probe_time);
			curr_pack=curr_pack->next_pack;
			count++;
		}
		curr_summ->rtt_time=sum/count;
		sum=0, count=1;
	}
}

void print_num_rtts(probe_summary *root){
	printf("TTL | # probes sent\n");
	printf("-------------------\n\n");

	probe_summary *curr_summ;
	int count=0;
	int current_ttl=1;
	int last_hop=MAX_HOPS;
	for(curr_summ=root;curr_summ!=NULL;curr_summ=curr_summ->next){
		// do not print past destination reached
		if(curr_summ->ttl_num>last_hop) return;
		if(curr_summ->dest_reached==1) last_hop=curr_summ->ttl_num;
		if(curr_summ->ttl_num==current_ttl) count++;
		if(curr_summ->next==NULL||curr_summ->next->ttl_num==current_ttl+1){
			printf(" %d\t\t%d\n", curr_summ->ttl_num,count);
			count=0;
			current_ttl++;
		}
	}
}

void print_probes(probe_summary *root){
	probe_summary *curr = root;

	printf("Source: %s | Destination: %s\n", curr->ip_src, curr->ip_dst);
	printf("--------------------------------------------\n\n");
	
	while(curr!=NULL){
		printf("\nttl: %d", curr->ttl_num);
		printf("\nsrc_ip: %s", curr->ip_src);
		printf("\ndst_ip: %s", curr->ip_dst);
		printf("\ninter_ip: %s", curr->intermediate_ip);
		printf("\nsrc_port: %d", curr->port_src);
		printf("\ndst_port: %d", curr->port_dst);
		printf("\nicmp_id: %d", curr->icmp_idnum);
		printf("\nicmp_seqnum: %d", curr->icmp_seqnum);
		printf("\nreply_time: %f", curr->reply_time);
		printf("\nproto: %d", curr->probe_proto);
		printf("\nprobe_id: %d", curr->probe_id);
		printf("\nm_flag: %d", curr->curr_m_flag);
		printf("\ndst_reached: %d", curr->dest_reached);
		printf("\nfragments: %d\n", curr->fragment_count);
		curr=curr->next;
	}
}

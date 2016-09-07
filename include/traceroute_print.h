#ifndef TRACEROUTE_PRINT
#define TRACEROUTE_PRINT

// call other print functions
void print_summary(probe_summary *root);

// prints each intermediate router not including destination
// if no reply received from router then prints message and continue
void print_intermediate_routers(probe_summary *root);

// prints protocols used in examined instance of traceroute
void print_protocols(probe_summary *root);

// if packets have been fragmented, print ttl val, 
// datagram id, num fragments, and offset of last fragment
void print_fragments(probe_summary *root);

// prints average and standard deviation RTT times
// for each intermediate router
void print_time_stats(probe_summary *root);

// go through all probe summaries and update overall ttl time
void set_summary_rtts(probe_summary *root);

// gathers time summary data
void generate_ttl_data(probe_summary *root, ttl_summary **root_ttl_ptr);

// print number of probes sent per ttl val
void print_num_rtts(probe_summary *root);

// print summary of every probe summary object
void print_probes(probe_summary *root);

#endif
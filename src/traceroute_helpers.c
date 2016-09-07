#include <math.h>

double get_sd(double data[], int n){
    int i;
    double mean=0.0, sum_deviation=0.0;
    if(n==1) return 0.0;

    for(i=0; i<n; i++){
    	mean+=data[i];
    } 
    mean=mean/n;
    for(i=0; i<n;++i){
    	sum_deviation+=(data[i]-mean)*(data[i]-mean);
    }
    return sqrt(sum_deviation/n); 
}

double get_avg(double data[], int n){
    int i;
    double avg=0.0;
    if(n==0) return 0;
    
    for(i=0; i<n; i++)
        avg+=data[i];
    return avg/n;
}

const char *get_protocol_name(int code){
	if(code==1) return "ICMP";
	if(code==17) return "UDP";
	return "Code not supported";
}



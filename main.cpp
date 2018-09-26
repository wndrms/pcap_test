#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

struct ip *ip_header;
struct tcphdr *tcp_header;

void dump(u_char* p, int len){
	for(int i=0; i<len; i++){
		printf("%02x ", *p);
		p++;
		if(i%16==15) printf("\n");
	}
	printf("\n");
}
void analysis(const u_char *p, int len){
	struct ether_header *e_header;
	int ether_type;
	
	e_header = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	ether_type = ntohs(e_header->ether_type);
	
	printf("------Ether Header------\n");
	printf("Src Mac : ");
	printf("%02X", e_header->ether_shost[0]);
	for(int i=1; i<6; i++){
		printf(":%02X", e_header->ether_shost[i]);
	}
	printf("\n");

	printf("Dst Mac : ");
	printf("%02X", e_header->ether_dhost[0]);
	for(int i=1; i<6; i++){
		printf(":%02X", e_header->ether_dhost[i]);
	}
	printf("\n");
	printf("----------------------\n");
	
	
	if(ether_type == ETHERTYPE_IP){
		printf("------IP Header------\n");
		ip_header = (struct ip *)p;
		printf("Src Address : %s\n", inet_ntoa(ip_header->ip_src));
        printf("Dst Address : %s\n", inet_ntoa(ip_header->ip_dst));
        printf("----------------------\n");
        if(ip_header -> ip_p == IPPROTO_TCP){
        	printf("------TCP Header------\n");
        	tcp_header = (struct tcphdr *)(p + ip_header->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcp_header->source));
            printf("Dst Port : %d\n" , ntohs(tcp_header->dest));
            
			int i=0;
            int offset = ip_header->ip_hl+tcp_header->th_off;
            int length = len - sizeof(struct ether_header) - offset*4;
            p += offset*4;
			while(length-- && i<16){
	            printf("%02x ", *(p++)); 
	            if ((++i % 16) == 0) 
	                printf("\n");
	        }
		}
	}
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
	printf("\n");
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    //dump((u_char*)packet, header->caplen);
    	
	analysis((u_char*)packet, header->caplen);
	printf("\n");
  }

  pcap_close(handle);
  return 0;
}

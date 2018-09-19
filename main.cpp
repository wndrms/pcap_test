#include <pcap.h>
#include <stdio.h>

void dump(u_char* p, int len){
	for(int i=0; i<len; i++){
		printf("%02x ", *p);
		p++;
		if(i%16==15) printf("\n");
	}
	printf("\n");
}
void Eth_Mac(u_char* p){
	printf("Src MAC : ");
	printf("%02x", p[0]);
	for(int i=1; i<6; i++) printf(":%02x", p[i]);
	printf("\n");
	printf("Dst MAC : ");
	printf("%02x", p[6]);
	for(int i=7; i<12; i++) printf(":%02x", p[i]);
	printf("\n");
}

void ip(u_char* p){
	printf("Src ip : ");
	printf("%d", p[26]);
	for(int i=27; i<30; i++) printf(".%d", p[i]);
	printf("\n");
	printf("Dst ip : ");
	printf("%d", p[30]);
	for(int i=31; i<34; i++) printf(".%d", p[i]);
	printf("\n");
}
void tcp_port(u_char* p){
	printf("tcp_Src port : ");
	printf("%d\n", p[34]*256+p[35]);
	printf("tcp_Dst port : ");
	printf("%d\n", p[36]*256+p[37]);
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
	Eth_Mac((u_char*)packet);
	if(packet[12] == 0x08 && packet[13] == 0x00){
		 printf("ip type : ipv4\n");
		 ip((u_char*)packet);
		 if(packet[23] == 0x06){
			 printf("protocol : TCP\n");
			 tcp_port((u_char*)packet);
			 if(packet[34+packet[46]]!=NULL){
				for(int i=0; i<32 && packet[34+packet[46]+i]!=NULL; i++){
					printf("%02x ", packet[34+packet[46]+i]);
					if(i%16==15) printf("\n");
				}
				printf("\n");
			 }
			 else continue;
		 }
		 else continue;
	}
	else continue;
	
  }

  pcap_close(handle);
  return 0;
}
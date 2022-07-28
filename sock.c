#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <stdlib.h> 
#include <string.h>
 
#define BUFFER_MAX 2048
#define ETH_NAME    "ens33"

 
 typedef int int32;
 typedef unsigned int u_int32;
 typedef unsigned char u_char;
 typedef unsigned short u_short;
 
 typedef struct mac_frm_hdr {
     char dest_addr[6];	//destination MAC address shall be defined first.
     char src_addr[6];
     short type;
 }__attribute__((packed)) MAC_FRM_HDR;
 
 
 typedef struct ip_hdr{ 	//header of IPV4
    #ifdef __LITTLE_ENDIAN_BIFIELD
        u_char ip_len:4, ip_ver:4;
    #else
        u_char ip_ver:4, ip_len:4;
    #endif
 
    u_char  ip_tos;
    u_short ip_total_len;
    u_short ip_id;
    u_short ip_flags;
    u_char  ip_ttl;
    u_char  ip_protocol;
    u_short ip_chksum;
    u_int32 ip_src;
    u_int32 ip_dest;
}__attribute__((packed)) IP_HDR;
 
 
 typedef struct pcap_file_hdr {
   u_int32 magic;
   u_short ver_major;
   u_short ver_minor;
   int32 timezone;
   u_int32 sigfigs;
   u_int32 snaplen;
   u_int32 linktype;
}__attribute__((packed))PCAP_FILE_HDR;


typedef struct pcap_pkg_hdr {
    u_int32 time_sec;   //this represents the number of whole seconds of elapsed time.
    u_int32 time_usec;  //this is the rest of the elapsed time, represent it as a number of microseconds.
    u_int32 caplen;
    u_int32 len;
}__attribute__((packed)) PCAP_PKG_HDR;
 
 /* From the example above: tcpdump -dd -s 0 udp 
	struct sock_filter code[] = {

	{ 0x15, 0, 5, 0x000086dd },

	{ 0x30, 0, 0, 0x00000014 },

	{ 0x15, 6, 0, 0x00000011 },

	{ 0x15, 0, 6, 0x0000002c },

	{ 0x30, 0, 0, 0x00000036 },

	{ 0x15, 3, 4, 0x00000011 },

	{ 0x15, 0, 3, 0x00000800 },

	{ 0x30, 0, 0, 0x00000017 },

	{ 0x15, 0, 1, 0x00000011 },

	{ 0x6, 0, 0, 0x00040000 },

	{ 0x6, 0, 0, 0x00000000 },
	
	}; 
*/


 int main(int argc, char *argv[]){
 	int  SOCKET_SRC;
    char buf[BUFFER_MAX];
    int n_rd;
    int ret;
//    unsigned char *iphead, *ethhead;
	struct ifreq ethreq;

    if( (SOCKET_SRC = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0 )
	{
         perror("socket");
         close(SOCKET_SRC);
         exit(0);
    }
    
    /* Set the network card in promiscuos mode */
  	strncpy(ethreq.ifr_name,ETH_NAME,IFNAMSIZ);
  	if (ioctl(SOCKET_SRC,SIOCGIFFLAGS, &ethreq)==-1) {
    perror("ioctl");
    close(SOCKET_SRC);
    exit(1);
  	}
  	ethreq.ifr_flags|=IFF_PROMISC;
  	if (ioctl(SOCKET_SRC,SIOCSIFFLAGS, &ethreq)==-1) {
    perror("ioctl");
    close(SOCKET_SRC);
    exit(1);
  	}
    /*  input filter code  */
    char ch[100];
    char ch1[100];
    char str[100];
    printf("Please specify filtering requirements based on BPF\n");
    fgets(str,99,stdin);
    str[strlen(str)-1]='\0';
    strcpy(ch,"sudo tcpdump -dd ");
    strcpy(ch1," | tee myfilter.txt");
    strcat(ch, str);
    strcat(ch, ch1);
    printf("your filter code :\n");
    system(ch);
    printf("\n");
    
    FILE *data = NULL;
    int len = 0;
    char line[255] = {0};
    struct sock_filter code[100] = {0};

    if ((data = fopen("myfilter.txt","r")) == NULL) {
        printf("Can not open file\n");
        return 0;
    }
	while (fgets(line, 255, data)) {
        sscanf(line, "{ %hx, %hhd, %hhd, %x },", &code[len].code, &code[len].jt, &code[len].jf, &code[len].k);
        len++;
    }
//    for (int j = 0; j < len ; j++) {
//    	printf("{ %hx, %hhd, %hhd, %x },\n", code[j].code, code[j].jt,code[j].jf,code[j].k);
//	}
//    
    fclose(data);
	
    	
    /* Attach the filter to the socket */
    struct sock_fprog bpf = {
	bpf.len = len,
	bpf.filter = code,
	};
    if( (ret = setsockopt(SOCKET_SRC, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))))
    {
    	 perror("setsockopt");
    	 close(SOCKET_SRC);
    	 exit(1);
	}    
    
    /*  save pcap file header   */
 	PCAP_FILE_HDR pcap_file_hdr = {0};
	PCAP_PKG_HDR pcap_pkg_hdr = {0};
	struct timeval ts;
	FILE *pfile;
	pfile = fopen("fname.pcap", "wb");
	if(pfile == NULL){
    fprintf(stdout, "no file will be saved.\n");
	}else{
    pcap_file_hdr.magic = 0xa1b2c3d4;  //0xA1B2C3D4是pcap文件的固定文件识别头
    pcap_file_hdr.ver_major = 0x02;
    pcap_file_hdr.ver_minor = 0x04;
    pcap_file_hdr.timezone = 0x00;
    pcap_file_hdr.sigfigs = 0x00;
    pcap_file_hdr.snaplen = 0xff;
    pcap_file_hdr.linktype = 0x01;
    fwrite(&pcap_file_hdr, sizeof(pcap_file_hdr), 1, pfile);
	}
	printf("Start catching pkg\n");
	while(1){
	/*returns the number of bytes received*/ 
    n_rd = recvfrom(SOCKET_SRC, buf, BUFFER_MAX, 0, NULL, NULL); 
    if(n_rd < 46){
        fprintf(stdout, "Incomplete header, packet corrupt\n");
        continue;
    }
    printf("pkg size[%d] \n", n_rd);
    /*      analysis data     */
	
	MAC_FRM_HDR *mac_hdr; //define a Ethernet frame header
	IP_HDR *ip_hdr;       //define a IP header
	char *tmp1, *tmp2;
	int AND_LOGIC = 0xFF;
 
	mac_hdr = buf;	//buf is what we got from the socket program
	ip_hdr = buf + sizeof(MAC_FRM_HDR);
 
	tmp1 = mac_hdr->src_addr;
	tmp2 = mac_hdr->dest_addr;
	/* print the MAC addresses of source and receiving host */
	printf("MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X==>" "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X   ",
            tmp1[0]&AND_LOGIC, tmp1[1]&AND_LOGIC, tmp1[2]&AND_LOGIC,tmp1[3]&AND_LOGIC,
            tmp1[4]&AND_LOGIC, tmp1[5]&AND_LOGIC,
            tmp2[0]&AND_LOGIC, tmp2[1]&AND_LOGIC, tmp2[2]&AND_LOGIC,tmp2[3]&AND_LOGIC,
            tmp2[4]&AND_LOGIC, tmp2[5]&AND_LOGIC);
 
	tmp1 = (char*)&ip_hdr->ip_src;
	tmp2 = (char*)&ip_hdr->ip_dest;
	/* print the IP addresses of source and receiving host */
	printf("IP: %d.%d.%d.%d => %d.%d.%d.%d",
             tmp1[0]&AND_LOGIC, tmp1[1]&AND_LOGIC, tmp1[2]&AND_LOGIC,tmp1[3]&AND_LOGIC,
             tmp2[0]&AND_LOGIC, tmp2[1]&AND_LOGIC, tmp2[2]&AND_LOGIC,tmp2[3]&AND_LOGIC);
	/* print the IP protocol which was used by the socket communication */
	switch(ip_hdr->ip_protocol) {
         case IPPROTO_ICMP: printf("   Protocol:ICMP\n"); break;
         case IPPROTO_IGMP: printf("   Protocol:IGMP\n"); break;
         case IPPROTO_IPIP: printf("   Protocol:IPIP\n"); break;
         case IPPROTO_TCP:
 	 	 case IPPROTO_UDP:
                            printf("   Protocol: %s\n", ip_hdr->ip_protocol == IPPROTO_TCP ? "TCP" : "UDP");
                            break;
         case IPPROTO_RAW: printf("   Protocol:RAW\n"); break;
         default: printf("Unknown, please query in inclued/linux/in.h\n"); break;
}
	
	/*     Save data in pcap format     */ 
    if(pfile != NULL){
        gettimeofday(&ts, NULL);
        pcap_pkg_hdr.time_usec = ts.tv_usec;
        pcap_pkg_hdr.time_sec = ts.tv_sec;
        pcap_pkg_hdr.caplen = n_rd;
        pcap_pkg_hdr.len = n_rd;
        fwrite(&pcap_pkg_hdr, sizeof(pcap_pkg_hdr), 1, pfile);
        fwrite(buf, n_rd, 1, pfile);
        /* termination control */
		}
	}
	return 0;
}


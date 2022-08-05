/*
	Octopus是一个基于Linux系统的一个简单网络数据采集分析工具。 
	Octopus可以抓取并打印出与布尔表达式匹配的网络接口上数据包
	内容，也可以将数据包内容保存为pacp格式通过wireshark打开分
	析。
	Octopus支持针对网络层、协议、主机、网络或端口的过滤，并提
	供and、or、not等逻辑语句来帮助你去掉无用的信息。 
	Octopus过滤机制使用内核的BPF过滤（伯克利数据包过滤器，Be-
	rkeley Packet Filter，工作在操作系统的内核态。)
	
	
    	./Octopus [ -c count ] [ -w file ] [ -v ]  [ -d filter ] [ -i interface ]
  	
  	-c   收到count个计数包后退出。
  	-w   将收到的文件以pacp格式保存在file路径文件中
	-v   在命令行简单分析数据包
	-d   为程序添加数据采集过滤规则
	     比如：
		 'tcp port 80 and udp'   只抓取来自端口80的udp数据包
		 'tcp port 23 and host 192.168.1.120'   获取主机192.168.1.120接收或发出的telnet包 
  	-i   指定网卡 
  	
  	
  	运行Octopus需要有sudo权限 
  	
  	如果Octopus没有运行-c标志，它将继续捕获数据包，直到它被一
	个SIGINT信号（例如，通过输入中断字符，通常为control-C）或
	一个SIGTERM信号（通常由kill（1）命令）; 如果使用-c 标志运
	行，它将捕获数据包，直到它被SIGINT或SIGTERM信号中断或指定
	的数据包已被处理。
	
*/

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <sys/time.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <stdlib.h> 
#include <string.h>

#define BUFFER_MAX 2048


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

void analysis(char *buf);
struct sock_fprog AddFilter(char Filter[] ,char ETHNAME[] ,int FlagEth ,char *devStr);

 int main(int argc, char *argv[]){
  	int  SOCKET_SRC;
  	char buf[BUFFER_MAX];
  	char Filter[100];
	char str[100];
	char errBuf[2048];
   	char ETHNAME[100];
   	int FlagSave = 0;
   	char *space = " ";
   	int FlagAnalysis = 0;
   	int FlagEth = 0;
   	int FlagFilter = 0;
   	int max = 9999;
   	int n_rd;
   	int ret;
   	int id = 0;
   	struct sock_filter code[100] = {0};
	struct ifreq ethreq;
	PCAP_FILE_HDR pcap_file_hdr = {0};
	PCAP_PKG_HDR pcap_pkg_hdr = {0};
	struct timeval ts;
	FILE *pfile;
	char *devStr;
	
	for(int i = 1;i < argc; i++)
	{
		if(*argv[i] == '-')
		{
			switch (*(argv[i]+1))
			{
				case 'w':
					FlagSave = 1;
					if(i+1 < argc)
					{
					strncpy(str,(argv[i+1]),99);
					}
					else
					{
					printf("input error\n");
					return 0;
					}
					break;
				case 'v':
					FlagAnalysis = 1;
					break;
				case 'd':
					FlagFilter = 1;
					if(i+1 < argc)
					{
					strncpy(Filter,(argv[i+1]),99);
					int j = i+2;
					while(j < argc)
					{
					if(*argv[j] == '-')break;
					strcat(Filter,space);
					strcat(Filter,(argv[j]));
					j++;
					}
					}
					else
					{
					printf("input error\n");
					return 0;
					}
					break;
				case 'c':
					if(i+1 < argc)
					{
					max = atoi(argv[i+1]);
					if(max == 0)
					   {
					    printf("input error\n");
					    return 0;
					   }
					}
					else
					{
					printf("input error\n");
					return 0;
					}
					break;
				case 'i':
					FlagEth = 1;
					if(i+1 < argc)
					{
					strncpy(ETHNAME,(argv[i+1]),99); 
					}
					else
					{
					printf("input error\n");
					return 0;
					}
					break;
			}
		}
	}

    if( (SOCKET_SRC = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0 )
	{
         perror("socket");
         close(SOCKET_SRC);
         exit(0);
    	}
    if(FlagEth)
    {
    	strncpy(ethreq.ifr_name,ETHNAME,IFNAMSIZ);
    	if (ioctl(SOCKET_SRC,SIOCGIFFLAGS, &ethreq)==-1)
		{
   		perror("ioctl");
    	close(SOCKET_SRC);
    	exit(1);
  		}
	}
	else
	{
	/* Set the network card in promiscuos mode */
	devStr = pcap_lookupdev(errBuf);
	if (!devStr)
    {
        printf("error: lookupdev\n");
        exit(1);
    }
  	strncpy(ethreq.ifr_name,devStr,IFNAMSIZ);
  	if (ioctl(SOCKET_SRC,SIOCGIFFLAGS, &ethreq)==-1)
	{
    perror("ioctl");
    close(SOCKET_SRC);
    exit(1);
  	}
  	ethreq.ifr_flags|=IFF_PROMISC;
  	if (ioctl(SOCKET_SRC,SIOCSIFFLAGS, &ethreq)==-1) 
		{
    	perror("ioctl");
    	close(SOCKET_SRC);
    	exit(1);
  		}
	}
    /*  input filter code  */
    if(FlagFilter)
    {
	struct sock_fprog bpf = AddFilter(Filter ,ETHNAME ,FlagEth ,devStr);
    if( (ret = setsockopt(SOCKET_SRC, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))))
    	{
    	 perror("setsockopt");
    	 close(SOCKET_SRC);
    	 exit(1);
	}
    }    
	/*    save pcap file header      */
	if(FlagSave)
	{
    pfile = fopen(str, "wb");
	if(pfile == NULL)
	{
    fprintf(stdout, "no file will be saved.\n");
	}
	else
		{
    pcap_file_hdr.magic = 0xa1b2c3d4;  //0xA1B2C3D4是pcap文件的固定文件识别头
    pcap_file_hdr.ver_major = 0x02;
    pcap_file_hdr.ver_minor = 0x04;
    pcap_file_hdr.timezone = 0x00;
    pcap_file_hdr.sigfigs = 0x00;
    pcap_file_hdr.snaplen = 0xff;
    pcap_file_hdr.linktype = 0x01;
    fwrite(&pcap_file_hdr, sizeof(pcap_file_hdr), 1, pfile);
		}
	}
	/*returns the number of bytes received*/   
	printf("Start catching pkg\n");
	while(1)
	{
    n_rd = recvfrom(SOCKET_SRC, buf, BUFFER_MAX, 0, NULL, NULL); 
    if(n_rd < 46)
	{
        fprintf(stdout, "Incomplete header, packet corrupt\n");
        continue;
    	}
    printf("id = %d pkg size[%d] \n", id, n_rd);
    id++;
    if(FlagAnalysis)
	{
		analysis(buf);
	}
	/*     Save data in pcap format     */ 
    if(pfile != NULL)
		{
        gettimeofday(&ts, NULL);
        pcap_pkg_hdr.time_usec = ts.tv_usec;
        pcap_pkg_hdr.time_sec = ts.tv_sec;
        pcap_pkg_hdr.caplen = n_rd;
        pcap_pkg_hdr.len = n_rd;
        fwrite(&pcap_pkg_hdr, sizeof(pcap_pkg_hdr), 1, pfile);
        fwrite(buf, n_rd, 1, pfile);
        /* termination control */
		}
	if(id > max - 1)
		{
		break;
		}
	}
	if(pfile != NULL) 
	{
	fclose(pfile);
	}
	return 0;
}



void analysis(char *buf)
{
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
	switch(ip_hdr->ip_protocol) 
	{
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
}


struct sock_fprog AddFilter(char Filter[] ,char ETHNAME[] ,int FlagEth ,char *devStr)
{
    char errBuf[2048];
    if(FlagEth)
	{
	devStr = ETHNAME;
	}
	pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
	if (!device)
    {
        printf("error: open_live\n");
        exit(1);
    }
	struct bpf_program filter;
	struct sock_fprog bpf; 
    int ret = pcap_compile(device, &filter, Filter, 1, 0);
    if(ret < 0)
	{
	printf("compile error\n");
	}
    bpf.len = filter.bf_len;
        struct sock_filter code[100];
	struct bpf_insn *bf;
	bf = filter.bf_insns;
	for(int i = 0;i < bpf.len;i++)
	{
	code[i].code = bf[i].code;
	code[i].jt = bf[i].jt;
	code[i].jf = bf[i].jf;
	code[i].k = bf[i].k;
	}
	bpf.filter = code;
	return bpf;
}

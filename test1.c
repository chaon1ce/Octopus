#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

  int * id = (int *)arg;

  pcap_dump(arg, pkthdr, packet);
  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  
/* int i;
  for(i=0; i<pkthdr->len; ++i)
  {
    printf(" %02x", packet[i]);
    if( (i + 1) % 16 == 0 )
    {
      printf("\n");
    }
  }
  
  printf("\n\n");   */
}
 
int main()
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    char buff[100];
    printf("Please specify dev\nEnter no if not required\n");
    fgets(buff, 99, stdin);
    
    if(strncmp(buff,"no",2) == 0)
    	devStr = pcap_lookupdev(errBuf);
    else
    	devStr = buff;
    if (devStr)
        printf("success: device: %s\n", devStr);
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }
 
    /* open a device, wait until a packet arrives */
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if (!device)
    {
        printf("error: pcap_open_live(): %s\n", errBuf);
        exit(1);
    }
 
    /*open pcap write output file*/
    pcap_dumper_t* out_pcap;
    out_pcap  = pcap_dump_open(device,"pack.pcap");
    
    /* construct a filter */
    char str[100];
    char *string = str;
    printf("Please specify filtering requirements based on BPF\n");
    fgets(string, 99, stdin);
    struct bpf_program filter;
    int ret = pcap_compile(device, &filter, string, 1, 0);
    if(ret < 0)
    		printf("pcap_compile error\n");
    else
        ret = pcap_setfilter(device, &filter);
    if(ret < 0)
		printf("pcap_compile error\n");
    
 
    /*Loop forever & call processPacket() for every received packet.*/
    pcap_loop(device, 20, processPacket, (u_char *)out_pcap);
 
    /*flush buff*/
    pcap_dump_flush(out_pcap);
    
    pcap_dump_close(out_pcap);
    pcap_close(device);
    return 0;
}

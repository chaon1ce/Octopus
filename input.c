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



int main(){ 
	FILE *data;//要读取的文件指针
    int i=0;
    char ch[100]= {0};
    if((data=fopen("myfilter.txt","r"))==NULL){
        printf("Can not open file\n");
        return 0;
    }
    int len=0;
    char line[255] = {0};
	while( fgets(line ,255, data) )
	{
		len++;
	}
    printf("%d",len);
    struct sock_filter code[100] = { };
    for (i = 0; i < len; ++i)
    {
        //fscanf(data, "{ 0x%, %d, %d, 0x%x },",code[i].code,code[i].jt,code[i].jf,code[i].k);
        fscanf(data, "{ 0x%x, %d, %d, 0x%x },", code[i].code,code[i].jt,code[i].jf,code[i].k);
	 }
    for(i = 0; i < len ;i++)
    {
    	printf("{ 0x%x, %d, %d, 0x%x },", code[i].code,code[i].jt,code[i].jf,code[i].k);
	}
    fclose(data);
	return 0;
	}

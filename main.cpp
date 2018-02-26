#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pcap.h"
#include "libnet.h"

#define MAX 16
struct pcap_device{
	pcap_t *handle;
	char device[8];
};

struct libnet_device{
	libnet_t *l;
	char detect_ip[16];
	char device[8];
	u_char src_mac[6];
	u_char dst_mac[6];
};

struct pcap_device *pcap_inuse;
struct libnet_device *libnet_inuse;
char errbuf[2048];

int sendpacket(u_int8_t *payload, u_int32_t payload_len)
{
	libnet_ptag_t eth = 0;
	eth = libnet_build_ethernet(
			libnet_inuse->dst_mac,
			libnet_inuse->src_mac,
			ETHERTYPE_IP,
			payload,
			payload_len,
			libnet_inuse->l,
			eth);

	if(eth == -1)
	{
		fprintf(stderr, "Can't build ethernet header:%s\n", libnet_geterror(libnet_inuse->l));
		return -1;
	}

	if(libnet_write(libnet_inuse->l) == -1)
	{
		fprintf(stderr, "send packet error:%s\n", libnet_geterror(libnet_inuse->l));
		return -1;
	}
	libnet_clear_packet(libnet_inuse->l);
	return 0;
}

/* init libpcap */
int lpcap_init()
{
	pcap_inuse = (struct pcap_device *)malloc(sizeof(struct pcap_device));
	memset(pcap_inuse, 0, sizeof(struct pcap_device));
	if(pcap_inuse == NULL)
	{
		fprintf(stderr, "malloc struct pcap_device error!\n");
		return -1;
	}

	if((pcap_inuse->handle = pcap_open_offline("./cert.pcap", errbuf)) == NULL)
	{
		fprintf(stderr, "pcap_open_offline error!\n");
		return -1;
	}
	return 0;

}

/* init libnet */
int lnet_init()
{
	libnet_inuse = (struct libnet_device *)malloc(sizeof(struct libnet_device));
	memset(libnet_inuse, 0, sizeof(struct libnet_device));
	if(libnet_inuse == NULL)
	{
		fprintf(stderr, "malloc libnet_device error!\n");
		return -1;
	}
	libnet_inuse->l = libnet_init(LIBNET_LINK, "eth0", NULL);
	if(libnet_inuse->l == NULL)
	{
		fprintf(stderr, "libnet init error!\n");
		return -1;
	}

	struct libnet_ether_addr *mac_addr = libnet_get_hwaddr(libnet_inuse->l);
	memcpy(libnet_inuse->src_mac, mac_addr->ether_addr_octet, 6);
	libnet_inuse->dst_mac[0] = 0xB8;
	libnet_inuse->dst_mac[1] = 0xAE;
	libnet_inuse->dst_mac[2] = 0xED;
	libnet_inuse->dst_mac[3] = 0xA7;
	libnet_inuse->dst_mac[4] = 0x99;
	libnet_inuse->dst_mac[5] = 0x27;
	return 0;
}


int start_thread_func(void*(*func)(void*), pthread_t* pthread,void * par)
{
    memset(pthread, 0, sizeof(pthread_t));
    int temp;
        /*创建线程*/
        if((temp = pthread_create(pthread, NULL, func, par)) != 0)
        printf("线程创建失败!/n");
        else
    {
        int id = pthread_self();
                printf("线程%u被创建/n", *pthread);
    }
    return temp;
}


/*
    结束线程
    pthread     线程函数所在pthread变量
    COM_STATU   线程函数状态控制变量 1:运行 0:退出
*/
int stop_thread_func(pthread_t* pthread)
{
    printf("prepare stop thread %u/n", *pthread);
    if(*pthread !=0)
    {
                pthread_join(*pthread, NULL);
    }
    printf("线程%退出!/n");
}



int main(int argc, char *argv[])
{
	if(!lpcap_init())
	{
		fprintf(stdout, "lpcap_init success!\n");
	}
	else
	{
		fprintf(stderr, "lpcap_init error!\n");
		exit(EXIT_FAILURE);
	}

	if(!lnet_init())
	{
		fprintf(stdout, "lnet_init success!\n");
	}
	else
	{
		fprintf(stderr, "lnet_init error!\n");
		exit(EXIT_FAILURE);
	}

    pthread_t thread[MAX];

	struct pcap_pkthdr *pkthdr;
	u_char *new_pkt;
	u_char pkt[1500] = {0};
	u_char payload[1500] = {0};
	int ret;
	while(1)
	{
		if(pcap_next_ex(pcap_inuse->handle, &pkthdr, (const u_char **)&new_pkt) == 1)
		{
			memset(pkt, 0, 1500);
			memcpy(pkt, new_pkt, 1500);
			struct ip *iph;
			int payload_len;
			iph = (struct ip *)(pkt + 14);
			payload_len = ntohs(iph->ip_len);

			int a = 0, b = 0, c = 0, d = 0;
			char sip[16] = {0};

            int thread_id;
            int s;
            //int d;
            for(a=0; a<MAX; a++)
        {

			for(i = 0; b < 1; b++)
			{
				memset(sip, 0, 16);
				for(j = 0; c < 100; c++)
				{
					for(m = 0; d < 100; d++)
					{
						snprintf(sip, 16, "%d.%d.%d.%d",a,b,c,d);
						//printf("sip:%s\n", sip);
						memset(payload, 0, 1500);
						iph->ip_src.s_addr = inet_addr(sip);
						//iph->ip_src.s_addr = inet_addr("192.168.1.1");
						//iph->ip_dst.s_addr = inet_addr("248.36.168.140");
						iph->ip_dst.s_addr = inet_addr("192.168.1.1");
                        s = ntohs(sip);
                        thread_id = a;
						memcpy(payload, pkt + 14, payload_len);
						//ret = sendpacket(payload, payload_len);
						ret = start_thread_func(sendpacket, &thread[thread_id],0);
                        if(ret!= 0)
                       {
                              printf("error to leave/n");
                              return -1;
                       }
                        printf("packet send by thread%d\n",  thread_id);
						usleep(50);
						/*
						   for(j = 0; j < 32; j++)
						   {
						   printf("%02x ", payload[j]);
						   }
						   printf("\n");
						   */
					}
				}
			}
        }
			printf("send ok!\n");
			sleep(12);
		}
		//usleep(1000000);
	}

int i;
for(i = 0;i<MAX;i++)
{
    stop_thread_func(&thread[i]);
}
	return 0;

}

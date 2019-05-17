#include "libnet_PlusPlus.h"


int main()
{



	pcap_t *handle = 0;
	pcap_if_t* alldevs;

	char err[1000] = {0};
	pcap_findalldevs(&alldevs, err);

	pcap_if_t *tmpDevsce = alldevs;
	while (tmpDevsce)
	{
		printf("devsceName  = %s", tmpDevsce->name);
		if (tmpDevsce->description)
		{
			printf(" 网卡= (%s)\n", tmpDevsce->description);
		}
		else
		{
			printf(" (No description available)\n");
		}

		tmpDevsce = tmpDevsce->next;
	}

	//LPADAPTER lpAdapter = PacketOpenAdapter(alldevs->next->name);
	//if (lpAdapter->Flags == INFO_FLAG_NDISWAN_ADAPTER || lpAdapter->Flags == INFO_FLAG_DONT_EXPORT)
	//{
	//	PacketCloseAdapter(lpAdapter);
	//	return 0;
	//}


	//Libnet libnet;
	//char errorBuf[256] = { 0 };
	//libnet_t *L = libnet.libnet_Init(LIBNET_RAW4, alldevs->next->name,errorBuf);


	//printf("%s", errorBuf);



	//libnet.libnet_Destroy(L);




	int end = 0;

	//libnet_t *l;
	//char *cp;
	//char errbuf[LIBNET_ERRBUF_SIZE] = { };
	//int c, whole_speed = 0, thread_num = 1;
	//pcap_t *handle = 0;
	//pcap_if_t* alldevs;

	//char err[1000];    //要是读者有疑问,可以留言,我看到就回
	//pcap_findalldevs(&alldevs, err);
	//pcap_if_t *d;
	//int inum, i = 0;
	//for (d = alldevs; d; d = d->next)
	//{
	//	printf("i = %d , d = %s", ++i, d->name);
	//	if (d->description)
	//		printf(" 网卡 = (%s)\n", d->description);
	//	else
	//		printf(" (No description available)\n");
	//}

	//char* name;
	//name = alldevs->name;
	//name = alldevs->next->name;
	//l = libnet_init(
	//	LIBNET_RAW4,                            /* injection type */
	//	name,                                   /* network interface */
	//	errbuf);                                /* error buffer */

	//if (l == NULL)
	//{
	//	fprintf(stderr, "libnet_init() failed: %s", errbuf);
	//	exit(EXIT_FAILURE);
	//}
	//char w[] = "www.baidu.com";
	//u_int32_t dstip = libnet_name2addr4(l, w, LIBNET_RESOLVE);
	//printf("www.baidu.com ip = %s\n", inet_ntoa(*((struct in_addr*)&dstip)));

	//libnet_ptag_t tcp = libnet_build_tcp(2000, 80, 0, 0, TH_SYN, 1024, 0, 0, 20, NULL, 0, l, 0);
	//srand(GetTickCount());
	//int src = rand() % 123456;
	//libnet_ptag_t ip = libnet_build_ipv4(20, 20 + 20, 0, 0, 64, 6/*"tcp"*/, 0, src, dstip, NULL, 0, l, 0);
	//while (true)
	//{
	//	int tag = libnet_write(l);

	//	if (tag < 1)
	//	{
	//		libnet_destroy(l);
	//		l = NULL;
	//		printf("错误");
	//	}

	//}


	//printf("本机的IP = ");

	//libnet_destroy(l);
	//l = NULL;


	system("pause");
	return 0;
}
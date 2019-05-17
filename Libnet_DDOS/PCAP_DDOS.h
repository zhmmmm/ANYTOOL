#pragma once
#include <thread>
#include <iostream>
#include <pcap.h>
#include <Windows.h>
using namespace std;

#define STOP FALSE

struct EthernetHeader
{
	u_char DestMAC[6];
	u_char SourMAC[6];
	u_short EthType;
};
struct IpHeader
{
	unsigned char Version_HLen;
	unsigned char TOS;
	short Length;
	short Ident;
	short Flags_Offset;
	unsigned char TTL;
	unsigned char Protocol;
	short Checksum;
	unsigned int SourceAddr;
	unsigned int DestinationAddr;
};
struct PsdTcpHeader
{
	unsigned long SourceAddr;
	unsigned long DestinationAddr;
	char Zero;
	char Protcol;
	unsigned short TcpLen;
};
struct TcpHeader
{
	unsigned short SrcPort;
	unsigned short DstPort;
	unsigned int SequenceNum;
	unsigned int Acknowledgment;
	unsigned char HdrLen;
	unsigned char Flags;
	unsigned short AdvertisedWindow;
	unsigned short Checksum;
	unsigned short UrgPtr;
};



class DDOS
{
	char m_Target_IP[256] = { 0 };
	int m_Target_Port = 0;
	int m_Threads = 0;
	unsigned char m_SendBuffer[200];

	pcap_if_t *m_NetwokDevice = NULL;
	char m_WinpcapError[PCAP_ERRBUF_SIZE];
	char m_DeviceName[100][256] = { 0 };
	int m_DeviceIndex = 0;
	pcap_t *m_WinpcapHandle = NULL;

	struct EthernetHeader m_ethernet;
	struct IpHeader m_IPHeader;
	struct TcpHeader m_TCPHeader;
	struct PsdTcpHeader m_PsdTCPHeader;
	char m_TcpData[15] = "Tcp Data Test.";


	BOOL m_Stop = TRUE;
public:
	DDOS();
	DDOS(const char *WEB, int Port = 80, int Threads = 10);
	~DDOS();
	unsigned int GetWEB_IP(const char *WEB);
	char *GetWEB_IP_s(const char *WEB,char *Buf);
	char *GetWEB_IP_s(const char *WEB);
	BOOL InitDdos(const char *IP, int Port = 80, int Threads = 10);
	void Run();
	void Thread_Run(){}
private:
	unsigned short checksum(unsigned short *data, int length);
};
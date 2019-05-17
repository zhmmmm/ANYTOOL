#pragma once
#include <stdio.h> 
#include <winsock2.h> 
#include <ws2tcpip.h> 
#include <time.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#pragma comment(lib,"ws2_32.lib")

#define IPVER   4           //IP协议预定
#define MAX_BUFF_LEN 65500  //发送缓冲区最大值

typedef struct ip_hdr    //定义IP首部 
{
	UCHAR h_verlen;            //4位首部长度,4位IP版本号 
	UCHAR tos;                //8位服务类型TOS 
	USHORT total_len;        //16位总长度（字节） 
	USHORT ident;            //16位标识 
	USHORT frag_and_flags;    //3位标志位 
	UCHAR ttl;                //8位生存时间 TTL 
	UCHAR proto;            //8位协议 (TCP, UDP 或其他) 
	USHORT checksum;        //16位IP首部校验和 
	ULONG sourceIP;            //32位源IP地址 
	ULONG destIP;            //32位目的IP地址 
}IP_HEADER;

typedef struct tsd_hdr //定义TCP伪首部 
{
	ULONG saddr;    //源地址
	ULONG daddr;    //目的地址 
	UCHAR mbz;        //没用
	UCHAR ptcl;        //协议类型 
	USHORT tcpl;    //TCP长度 
}PSD_HEADER;

typedef struct tcp_hdr //定义TCP首部 
{
	USHORT th_sport;            //16位源端口 
	USHORT th_dport;            //16位目的端口 
	ULONG th_seq;                //32位序列号 
	ULONG th_ack;                //32位确认号 
	UCHAR th_lenres;            //4位首部长度/6位保留字 
	UCHAR th_flag;                //6位标志位 
	USHORT th_win;                //16位窗口大小 
	USHORT th_sum;                //16位校验和 
	USHORT th_urp;                //16位紧急数据偏移量 
}TCP_HEADER;



class DOS
{
	char m_IP[256] = { 0 };
	int m_Port = 0;
	int m_Thread = 0;

	SOCKET m_Socket = -1;

	IP_HEADER m_IPHeader;
	TCP_HEADER m_TCPHeader;
	PSD_HEADER m_PSDHeader;

	char m_Sendto_Buffer[MAX_BUFF_LEN] = { 0 };  //发送缓冲区
	unsigned short m_check_Buff[MAX_BUFF_LEN] = { 0 }; //检验和缓冲区
	const char m_send_data[256] = "This is my homework of networt,I am happy!" ;
public:
	DOS();
	~DOS();
	BOOL InitDos(const char *IP = "180.97.33.107",int Port = 80,int Thread = 0);
	void Run();
	char *GetSendData() { return m_Sendto_Buffer; }
private:
	void CloseSocket();
	//CheckSum:计算校验和的子函数 
	USHORT checksum(USHORT *buffer, int size);
	void CheckSum();
};
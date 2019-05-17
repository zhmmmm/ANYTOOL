#pragma once
#include <iostream>
#include <vector>

#include "../Memory/Memory.h"//内存池

#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")


#include "../Package/SendPackage.h"
#include "../Package/RecvPackage.h"
#include "../TCP/TCPPROTOCOLFAMILY.h"

typedef struct STATE
{
	int Connect = 0;
}States;

class TcpClient;
class Users
{
	SendPackage m_SendPackage;
	RecvPackage m_RecvPackage;


	States m_State;
public:


	void User_Dataed(const void *Data, int DataSize, TcpClient &Server);
	States *GetState();

	SendPackage *GetSendPackage();
	RecvPackage *GetRecvPackage();
private:
	void _Program();
};


class TcpClient
{

	SOCKET m_ListenSocket;
	sockaddr_in *m_Si = NULL;
	Users m_User;
	int m_MaxRecv = 1000;//最大接受长度
public:
	BOOL InisSocket();
	SOCKET ConnectServer();
	void RunClient();
	void CloseSocket();
	void Sends(const void *Data, int Size);
	void Recvs(void *Data, int Size);
	Users *GetUsers();
private:
	SOCKET _Accept(SOCKET Socket);
	int _Recv(SOCKET Socket, char *Buf, int Len);
	int _Send(SOCKET Socket, char *Buf, int Len);



	//内存池
	MemoryPool m_MemoryPool;
	//发送数据包
	struct SENDDATA
	{
		//发送数据的首地址
		char* data = NULL;
		//发送数据的总长度
		int size = 0;
		//已经发送的长度
		int send_size = 0;
	};
	//接受数据
	struct RECVDATA
	{
		char* recv_data = NULL;
		int recv_size = 0;
	};

	std::vector<SENDDATA> m_SendData;
	RECVDATA m_RecvData;

	//返回-1：发生网络错误
    //返回0：发送缓冲区已满暂时不能发送数据
    //返回>0：已经发送了多少字节
	static int my_send(SOCKET sock, char* buf, int len);

	//返回-2：接收缓冲区是空的当前不可读
    //返回-1：发生网络错误
    //返回0：对方优雅断开
    //返回>0：读取了多少字节
	static int my_recv(SOCKET sock, char* buf, int len);

	int _Send();
	int _Recv();



};


#define GETCLIENT_TCP                                                 Client::GetInstense()->GetTcpClient()
#define GETCLIENTSENDPACKAGE                                          GETCLIENT_TCP->GetUsers()->GetSendPackage()
#define GETCLIENTRECVPACKAGE                                           GETCLIENT_TCP->GetUsers()->GetRecvPackage()



class Client
{

	TcpClient m_TcpClient;

public:

	static Client *GetInstense();

	Client();
	void RunClient();//发送与接收
	void CloseClient();
	TcpClient *GetTcpClient();
};

//=======================================================

#include "Client.h"

Client *Client::GetInstense()
{
	static Client Obj;

	return &Obj;
}

Client::Client()
{
	m_TcpClient.InisSocket();
}
void Client::RunClient()
{
	m_TcpClient.RunClient();
}
void Client::CloseClient()
{
	m_TcpClient.CloseSocket();
}
TcpClient *Client::GetTcpClient()
{
	return &m_TcpClient;
}


BOOL TcpClient::InisSocket()
{
	//开启网络环境
	WSADATA wd;
	WSAStartup(0x0202, &wd);
	//创建套字节
	m_ListenSocket = socket(
		AF_INET,
		SOCK_STREAM,
		IPPROTO_TCP);

	//填充服务器地址信息结构体
	char Server_ip[256] = "127.0.0.1";
	m_Si = new sockaddr_in;
	m_Si->sin_family = AF_INET;
	m_Si->sin_port = htons(12345);//服务器开放的湍口
	//m_Si->sin_addr.S_un.S_addr = inet_addr(Server_ip);
	if (inet_pton(AF_INET, Server_ip, (void*)&m_Si->sin_addr) < 0)
	{
		CloseSocket();
		return FALSE;
	}
	if (TcpClient::ConnectServer() == 0)
	{
		CloseSocket();
		return FALSE;
	}
	return TRUE;
}
SOCKET TcpClient::ConnectServer()
{
	if (0 != connect(m_ListenSocket, (sockaddr*)m_Si, sizeof(*m_Si)))
	{
		closesocket(m_ListenSocket);
		WSACleanup();
		return 0;
	}
	return m_ListenSocket;
}
void TcpClient::RunClient()
{

	TcpClient::_Send();//有发送的发送

	TcpClient::_Recv();//有接收的接收
	
}
void TcpClient::Sends(const void *Data, int Size)
{
	SENDDATA sd;
	sd.size = sizeof(int) + Size;
	sd.data = (char*)m_MemoryPool.Allocate(sd.size);
	*((int*)sd.data) = Size;
	memcpy(sd.data + sizeof(int), Data, Size);
	sd.send_size = 0;

	m_SendData.push_back(sd);
}
void TcpClient::Recvs(void *Data,int Size)
{
	m_User.User_Dataed(Data,Size,*this);
}
int TcpClient::my_send(SOCKET sock, char* buf, int len)
{
	fd_set fs;
	FD_ZERO(&fs);
	FD_SET(sock, &fs);
	timeval t = { 0, 0 };

	//多路复用判断可写性
	select(0, 0, &fs, 0, &t);

	//如果不可写
	if (0 == fs.fd_count)
		return 0;
	else
	{
		//send函数的返回值如果是SOCKET_ERROR就表示
		//当前的网络出错了，应该关闭套接字；否则其
		//返回值表示本次真正发送了多少字节，这个返
		//回值可能会比len小
		return send(sock, buf, len, 0);
	}
}
int TcpClient::my_recv(SOCKET sock, char* buf, int len)
{
	fd_set fs;
	FD_ZERO(&fs);
	FD_SET(sock, &fs);
	timeval t = { 0, 0 };

	//多路复用判断可读性
	select(0, &fs, 0, 0, &t);

	//如果不可读
	if (0 == fs.fd_count)
		return -2;
	else
	{
		//recv如果返回为0则表示对方优雅断开，返回
		//SOCKET_ERROR表示网络出错了，这两种情况下
		//都是客户端已经断开了，我们不能使用这个套
		//接字了，就应该关闭套接字；否则返回值就表
		//示收到了多少字节
		return recv(sock, buf, len, 0);
	}
}
int TcpClient::_Send()
{
	for (std::vector<SENDDATA>::iterator it = m_SendData.begin(); it != m_SendData.end();)
	{
		if (it->size == 0)//没有数据可以发送
		{
			return 0;
		}
		else//有数据可以发送
		{
			//退出标志
			//0：正常发送完毕
			//1：暂时不能发送
			//2：出现网络错误
			int qf = 0;

			//得到第0个数据包
			SENDDATA* sd = &(*(it));

			//循环发送数据
			while (sd->send_size < sd->size)
			{
				//发送本次数据
				int r = my_send(
					m_ListenSocket,
					sd->data + sd->send_size,
					sd->size - sd->send_size);

				//发送数据失败
				if (r <= 0)
				{
					//暂时不能发了
					if (0 == r)
					{
						qf = 1;
						break;
					}
					//出现网络错误
					else
					{
						qf = 2;
						break;
					}
				}
				else
				{
					//已经发送的字节数累积到send_size中
					sd->send_size += r;
				}
			}

			//根据跳出循环的不同进行分情况处理
			if (0 == qf)
			{
				//释放该包占据的堆内存
				m_MemoryPool.Free(sd->data);

				//发送完将该包从表中移除
				it = m_SendData.erase(it);
				//迭代
				//++it;
			}
			else if (1 == qf)
			{
				//迭代
				++it;
			}
			else
			{
				//从表中删除
				it = m_SendData.erase(it);
			}
		}
	}
	return 1;
}
int TcpClient::_Recv()
{
	if (m_RecvData.recv_data == NULL)
	{
		m_RecvData.recv_data = (char*)m_MemoryPool.Allocate(m_MaxRecv);

		for (int i = 0; i < m_MaxRecv; i++)
		{
			m_RecvData.recv_data[i] = 0;
		}

		int len = my_recv(m_ListenSocket, m_RecvData.recv_data, 4);
		//*((int*)m_RecvData.recv_data)
		if (len >= 4)
		{
			int AllData = *((int*)m_RecvData.recv_data); //再接收这么多个字节数据就完成了
			int len = my_recv(m_ListenSocket, m_RecvData.recv_data, AllData);//接着接收
			if (len == AllData)//数据接收完了
			{
				m_RecvData.recv_size = AllData;
				TcpClient::Recvs(m_RecvData.recv_data, m_RecvData.recv_size);
			}
			else
			{
				//哥们儿我们帮你重启
				exit(0);
			}
		}
	}
	else
	{
		for (int i = 0; i < m_MaxRecv; i++)
		{
			m_RecvData.recv_data[i] = 0;
		}

		int len = my_recv(m_ListenSocket, m_RecvData.recv_data, 4);
		//*((int*)m_RecvData.recv_data)
		if (len >= 4)
		{
			int AllData = *((int*)m_RecvData.recv_data); //再接收这么多个字节数据就完成了
			int len = my_recv(m_ListenSocket, m_RecvData.recv_data, AllData);//接着接收
			if (len == AllData)//数据接收完了
			{
				m_RecvData.recv_size = AllData;
				TcpClient::Recvs(m_RecvData.recv_data, m_RecvData.recv_size);
			}
			else
			{
				//哥们儿我们帮你重启
				exit(0);
			}
		}
	}


	return 1;
}
Users *TcpClient::GetUsers()
{
	return &m_User;
}






//==============================================================================

void Users::User_Dataed(const void *Data, int DataSize, TcpClient &Server)
{

	m_RecvPackage.set_data(Data, DataSize);

	int DATAID = INITAGREEMENT;

	if (m_RecvPackage.get_int(&DATAID))
	{
		switch (DATAID)
		{
		case CLIENTEXIT: 
		{
			Users::_Program();
		}break;
		case USER_CLIENTCONNECT:
		{

			char buf[256] = { 0 };
			m_RecvPackage.get_string(buf);

			std::cout << buf << std::endl;
			m_State.Connect = USER_CLIENTCONNECT;
		}break;
		}
	}

}
States *Users::GetState()
{
	return &m_State;
}

SendPackage *Users::GetSendPackage()
{
	return &m_SendPackage;
}
RecvPackage *Users::GetRecvPackage()
{
	return &m_RecvPackage;
}
//=========================================================回调
void Users::_Program()
{
	exit(0);
}





SOCKET TcpClient::_Accept(SOCKET Socket)
{
	fd_set Ls;
	FD_ZERO(&Ls);
	FD_SET(Socket, &Ls);
	timeval Time = { 0,0 };
	select(0, &Ls, 0, 0, &Time);
	if (Ls.fd_count > 0)
	{
		sockaddr_in Client_Si;
		int Client_si_Size = sizeof(Client_Si);

		SOCKET Data_Socket = accept(Socket, (sockaddr*)&Client_Si, &Client_si_Size);

		printf("接收到来自：地址 = %d.%d.%d.%d ， 端口： %d 的客户的连接\n",
			Client_Si.sin_addr.S_un.S_un_b.s_b1,
			Client_Si.sin_addr.S_un.S_un_b.s_b2,
			Client_Si.sin_addr.S_un.S_un_b.s_b3,
			Client_Si.sin_addr.S_un.S_un_b.s_b4,
			Client_Si.sin_port);
		return Data_Socket;
	}
	return INVALID_SOCKET;
}
int TcpClient::_Recv(SOCKET Socket, char *Buf, int Len)
{
	fd_set Rs;
	FD_ZERO(&Rs);
	FD_SET(Socket, &Rs);
	timeval Time = { 0,0 };
	select(0, &Rs, 0, 0, &Time);
	if (Rs.fd_count > 0)
	{
		/*
		//如果没有错误，recv返回接收到的字节数
		If no error occurs, recv returns the number of bytes received.
		//如果连接被优雅的断开，返回0
		If the connection has been gracefully closed, the return value is zero.
		//否则将返回一个SOCKET_ERROR（-1）
		Otherwise, a value of SOCKET_ERROR is returned,
		//并且我们可以通过WSAGetLastError来获取最后的错误代码
		and a specific error code can be retrieved by calling WSAGetLastError.
		*/
		return recv(Socket, Buf, Len, 0);
	}
	return -2;//表示没有接受到数据，但是套接字是正常的
}
int TcpClient::_Send(SOCKET Socket, char *Buf, int Len)
{
	fd_set Rs;
	FD_ZERO(&Rs);
	FD_SET(Socket, &Rs);
	timeval Time = { 0,0 };
	select(0, 0, &Rs, 0, &Time);
	if (Rs.fd_count > 0)
	{
		/*
		//如果没有错误，那么返回的是本次已经发送的总字节数
		If no error occurs, send returns the total number of bytes sent,
		//但是这个字节数可能比预期的少【甚至可能返回0，
		//但是套接字还是正常的，只是这一次没有发出去】
		which can be less than the number indicated by len.
		//否则的话返回一个套接字错误SOCKET_ERROR（-1）【套接字被断开啦】
		Otherwise, a value of SOCKET_ERROR is returned,
		//并且我们可以通过WSAGetLastError来获取最后的错误代码
		and a specific error code can be retrieved by calling WSAGetLastError.
		*/

		return send(Socket, Buf, Len, 0);
	}
	return 0;//表示不具备可写性
}
void TcpClient::CloseSocket()
{
	//关闭套接字
	closesocket(m_ListenSocket);
	WSACleanup();
	delete m_Si;
	m_Si = NULL;
}
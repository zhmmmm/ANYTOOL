#include "libnet_PlusPlus.h"

libnet_t *Libnet::libnet_Init(int Type, char *Device, char *err_buf)
{
	libnet_t *libnet = NULL;

	WSADATA wsaData;
	if ((WSAStartup(0x0202, &wsaData)) != 0)
	{
		printf("网络初始化失败！");
		return NULL;
	}

	libnet = new libnet_t;
	if (libnet)
	{
		printf("内存分配成功！");
	}

	memset(libnet,0,sizeof(libnet_t));

	libnet->injection_type = Type;
	libnet->ptag_state = 0;
	libnet->device = (Device ? _strdup(Device) : NULL);

	strcpy_s(libnet->label,LIBNET_LABEL_DEFAULT);
	libnet->label[sizeof(libnet->label)] = '\0';

	switch (libnet->injection_type)
	{
	case LIBNET_RAW4:
	{
		if (Libnet::libnet_Open_Raw4(libnet) == -1)
		{
			printf("%s\n",libnet->err_buf);
			Libnet::libnet_Destroy(libnet);
			return NULL;
		}
	}; break;
	}


	return libnet;
}
int Libnet::libnet_Open_Raw4(libnet_t *libnet)
{
	if (libnet == NULL) { return -1; }

	DWORD dwErrorCode;
	NetType IFType;

	if (libnet->device == NULL)
	{
		sprintf_s(libnet->err_buf,"%s","NULL device\n");
	}
	libnet->lpAdapter = 0;
	libnet->lpAdapter = PacketOpenAdapter(libnet->device);
	if (!libnet->lpAdapter || libnet->lpAdapter->hFile == INVALID_HANDLE_VALUE
		|| libnet->lpAdapter->Flags == INFO_FLAG_NDISWAN_ADAPTER 
		|| libnet->lpAdapter->Flags == INFO_FLAG_DONT_EXPORT)
	{
		sprintf_s(libnet->err_buf, "%s", "PacketOpenAdapter() 调用失败  \n");
		return -1;
	}

	//PacketSetBuff(libnet->lpAdapter, 512000);

	if (PacketGetNetType(libnet->lpAdapter, &IFType))
	{
		switch (IFType.LinkType)
		{
		//case NdisMedium802_3:
			//l->link_type = DLT_EN10MB;
		//	l->link_offset = LIBNET_ETH_H;
		//	break;
		//case NdisMedium802_5:
		//	l->link_type = DLT_IEEE802;
		//	l->link_offset = LIBNET_TOKEN_RING_H;
		//	break;
		//case NdisMediumFddi:
		//	l->link_type = DLT_FDDI;
		//	l->link_offset = 0x15;
		//	break;
		//case NdisMediumWan:
		//	snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
		//		"%s():, WinPcap has disabled support for Network type (%d)\n",
		//		__func__, IFType.LinkType);
		//	return (-1);
		//	break;
		//case NdisMediumAtm:
		//	l->link_type = DLT_ATM_RFC1483;
		//	break;
		//case NdisMediumArcnet878_2:
		//	l->link_type = DLT_ARCNET;
		//	break;
		//default:
		//	snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
		//		"%s(): network type (%d) is not supported\n",
		//		__func__, IFType.LinkType);
		//	return (-1);
		//	break;
		}
	}
	else
	{
		sprintf_s(libnet->err_buf, "%s", "PacketGetNetType() 调用失败  \n");
		return -1;
	}

	return 1;
}




void Libnet::libnet_Destroy(libnet_t *libnet)
{
	if (libnet)
	{
		closesocket(libnet->fd);
		if (libnet->device)
		{
			delete[] libnet->device;
			libnet->device = NULL;
		}

		Libnet::libnet_Clear_Packet(libnet);

		delete libnet;
		libnet = NULL;
	}
}
void Libnet::libnet_Clear_Packet(libnet_t *libnet)
{
	libnet_pblock_t *p = NULL;
	libnet_pblock_t *next = NULL;
	if (libnet)
	{
		p = libnet->protocol_blocks;
		if (p)
		{
			for (; p; p = next)
			{
				next = p->next;
				if (p->buf)
				{
					delete p->buf;
					p->buf = NULL;
				}
				delete p;
				p = NULL;
			}
		}
		libnet->protocol_blocks = NULL;
		libnet->total_size = 0;
	}
}
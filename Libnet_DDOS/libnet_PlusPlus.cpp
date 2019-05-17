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
	libnet->lpAdapter = PacketOpenAdapter(libnet->device);
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

	socklen_t len;
	BOOL n;

	libnet->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (libnet->fd == -1)
	{
		snprintf(libnet->err_buf, LIBNET_ERRBUF_SIZE,
			" SOCK_RAW allocation failed: %s",strerror(errno));
	}

#ifdef IP_HDRINCL
	n = TRUE;
	if (setsockopt(libnet->fd, IPPROTO_IP, IP_HDRINCL, (char*)&n, sizeof(n)) == -1)
	{
		snprintf(libnet->err_buf, LIBNET_ERRBUF_SIZE,
			"set IP_HDRINCL failed: %s",strerror(errno));
	}
#endif 


	if (libnet_finish_setup_socket(libnet) == -1)
	{
		return -1;
	}
	return 1;
}
unsigned int Libnet::libnet_Name2addr4(libnet_t *l, char *host_name, unsigned char use_name)
{
	struct in_addr addr;
	struct hostent *host_ent;
	unsigned int m;
	unsigned int val;
	int i;

	if (use_name == LIBNET_RESOLVE)
	{
		if ((addr.s_addr = inet_addr(host_name)) == -1)
		{
			if (!(host_ent = gethostbyname(host_name)))
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): %s", __func__,
#if (_WIN32)
					"gethostbyname failure"
#else
					/* FIXME doesn't exist on windows, needs WSAGetLastError()/FormatMessage */
					hstrerror(h_errno)
#endif
				);
				return (-1);
			}
			memcpy(&addr.s_addr, host_ent->h_addr, host_ent->h_length);
		}
		return (addr.s_addr);
	}
	else
	{
		if (!isdigit(host_name[0]))
		{
			if (l)
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): expecting dots and decimals", __func__);
			}
			return (-1);
		}

		m = 0;
		for (i = 0; i < 4; i++)
		{
			m <<= 8;
			if (*host_name)
			{
				val = 0;
				while (*host_name && *host_name != '.')
				{
					val *= 10;
					val += *host_name - '0';
					if (val > 255)
					{
						if (l)
						{
							snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
								"%s(): value greater than 255", __func__);
						}
						return (-1);
					}
					host_name++;
				}
				m |= val;
				if (*host_name)
				{
					host_name++;
				}
			}
		}
		return (ntohl(m));
	}
}
libnet_ptag_t Libnet::libnet_build_tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack,uint8_t control, uint16_t win, uint16_t sum, uint16_t urg, uint16_t h_len,const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
	int n, offset;
	libnet_pblock_t *p = NULL;
	libnet_ptag_t ptag_data = 0;
	struct libnet_tcp_hdr tcp_hdr;

	if (l == NULL)
		return -1;

	if (payload_s && !payload)
	{
		return -1;
	}

	p = libnet_pblock_probe(l, ptag, LIBNET_TCP_H, LIBNET_PBLOCK_TCP_H);
	if (p == NULL)
		return -1;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	tcp_hdr.th_sport = htons(sp);    /* source port */
	tcp_hdr.th_dport = htons(dp);    /* destination port */
	tcp_hdr.th_seq = htonl(seq);   /* sequence number */
	tcp_hdr.th_ack = htonl(ack);   /* acknowledgement number */
	tcp_hdr.th_flags = control;      /* control flags */
	tcp_hdr.th_x2 = 0;            /* UNUSED */
	tcp_hdr.th_off = 5;            /* 20 byte header */

	/* check to see if there are TCP options to include */
	if (p->prev && p->prev->type == LIBNET_PBLOCK_TCPO_H)
	{
		/* Note that the tcp options pblock is already padded */
		tcp_hdr.th_off += (p->prev->b_len / 4);
	}

	tcp_hdr.th_win = htons(win);   /* window size */
	tcp_hdr.th_sum = (sum ? htons(sum) : 0);   /* checksum */
	tcp_hdr.th_urp = htons(urg);          /* urgent pointer */

	n = libnet_pblock_append(l, p, (uint8_t *)&tcp_hdr, LIBNET_TCP_H);
	if (n == -1)
	{
		goto bad;
	}

	if (ptag == LIBNET_PTAG_INITIALIZER)
	{
		libnet_pblock_update(l, p, h_len, LIBNET_PBLOCK_TCP_H);
	}

	offset = payload_s;

	/* If we are going to modify a TCP data block, find it, and figure out the
	 * "offset", the possibly negative amount by which we are increasing the ip
	 * data length. */
	if (ptag)
	{
		libnet_pblock_t* datablock = p->prev;

		if (datablock && datablock->type == LIBNET_PBLOCK_TCPO_H)
			datablock = datablock->prev;

		if (datablock && datablock->type == LIBNET_PBLOCK_TCPDATA)
		{
			ptag_data = datablock->ptag;
			offset -= datablock->b_len;
		}
		p->h_len += offset;
	}

	/* If we are modifying a TCP block, we should look forward and apply the offset
	 * to our IPv4 header, if we have one.
	 */
	if (p->next)
	{
		libnet_pblock_t* ipblock = p->next;

		if (ipblock->type == LIBNET_PBLOCK_IPO_H)
			ipblock = ipblock->next;

		if (ipblock && ipblock->type == LIBNET_PBLOCK_IPV4_H)
		{
			struct libnet_ipv4_hdr * ip_hdr = (struct libnet_ipv4_hdr *)ipblock->buf;
			int ip_len = ntohs(ip_hdr->ip_len) + offset;
			ip_hdr->ip_len = htons(ip_len);
		}
	}

	/* if there is a payload, add it in the context */
	if (payload_s)
	{
		/* update ptag_data with the new payload */
		libnet_pblock_t* p_data = libnet_pblock_probe(l, ptag_data, payload_s, LIBNET_PBLOCK_TCPDATA);
		if (!p_data)
		{
			goto bad;
		}

		n = libnet_pblock_append(l, p_data, payload, payload_s);
		if (n == -1)
		{
			goto bad;
		}

		if (ptag_data == LIBNET_PTAG_INITIALIZER)
		{
			int insertbefore = p->ptag;

			/* Then we created it, and we need to shuffle it back until it's before
			 * the tcp header and options. */
			libnet_pblock_update(l, p_data, payload_s, LIBNET_PBLOCK_TCPDATA);

			if (p->prev && p->prev->type == LIBNET_PBLOCK_TCPO_H)
				insertbefore = p->prev->ptag;

			libnet_pblock_insert_before(l, insertbefore, p_data->ptag);
		}
	}
	else
	{
		libnet_pblock_t* p_data = libnet_pblock_find(l, ptag_data);
		libnet_pblock_delete(l, p_data);
	}

	if (sum == 0)
	{
		/*
		 *  If checksum is zero, by default libnet will compute a checksum
		 *  for the user.  The programmer can override this by calling
		 *  libnet_toggle_checksum(l, ptag, 1);
		 */
		libnet_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
	}
	return (p->ptag);
bad:
	libnet_pblock_delete(l, p);
	return (-1);
}
int Libnet::libnet_write(libnet_t *l)
{
	int c;
	uint32_t len;
	uint8_t *packet = NULL;

	if (l == NULL)
	{
		return (-1);
	}

	c = libnet_pblock_coalesce(l, &packet, &len);
	if (c == -1)
	{
		/* err msg set in libnet_pblock_coalesce() */
		return (-1);
	}

	/* assume error */
	c = -1;
	switch (l->injection_type)
	{
	case LIBNET_RAW4:
	case LIBNET_RAW4_ADV:
		if (len > LIBNET_MAX_PACKET)
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): packet is too large (%d bytes)",
				__func__, len);
			goto done;
		}
		c = libnet_write_raw_ipv4(l, packet, len);
		break;
	case LIBNET_RAW6:
	case LIBNET_RAW6_ADV:
		c = libnet_write_raw_ipv6(l, packet, len);
		break;
	case LIBNET_LINK:
	case LIBNET_LINK_ADV:
		c = libnet_write_link(l, packet, len);
		break;
	default:
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): unsuported injection type", __func__);
		goto done;
	}

	/* do statistics */
	if (c == len)
	{
		l->stats.packets_sent++;
		l->stats.bytes_written += c;
	}
	else
	{
		l->stats.packet_errors++;
		/*
		 *  XXX - we probably should have a way to retrieve the number of
		 *  bytes actually written (since we might have written something).
		 */
		if (c > 0)
		{
			l->stats.bytes_written += c;
		}
	}
done:
	/*
	 *  Restore original pointer address so free won't complain about a
	 *  modified chunk pointer.
	 */
	if (l->aligner > 0)
	{
		packet = packet - l->aligner;
	}
	free(packet);
	return (c);
}
libnet_ptag_t Libnet::libnet_build_ipv4(uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag,uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src, uint32_t dst,const uint8_t* payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
	uint32_t n = LIBNET_IPV4_H; /* size of memory block */
	libnet_pblock_t *p, *p_data, *p_temp;
	struct libnet_ipv4_hdr ip_hdr;
	libnet_ptag_t ptag_data = 0; /* used if there is ipv4 payload */
	libnet_ptag_t ptag_hold;

	if (l == NULL)
	{
		return (-1);
	}

	/*
	 *  Find the existing protocol block if a ptag is specified, or create
	 *  a new one.
	 */
	p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_IPV4_H);
	if (p == NULL)
	{
		return (-1);
	}

	memset(&ip_hdr, 0, sizeof(ip_hdr));
	ip_hdr.ip_v = 4;      /* version 4 */
	ip_hdr.ip_hl = 5;      /* 20 byte header,  measured in 32-bit words */

	/* check to see if there are IP options to include */
	if (p->prev)
	{
		if (p->prev->type == LIBNET_PBLOCK_IPO_H)
		{
			/* IPO block's length must be multiple of 4, or it's incorrectly
			 * padded, in which case there is no "correct" IP header length,
			 * it will too short or too long, we choose too short.
			 */
			ip_hdr.ip_hl += p->prev->b_len / 4;
		}
	}
	/* Note that p->h_len is not adjusted. This seems a bug, but it is because
	 * it is not used!  libnet_do_checksum() is passed the h_len (as `len'),
	 * but for IPPROTO_IP it is ignored in favor of the ip_hl.
	 */

	ip_hdr.ip_tos = tos;                       /* IP tos */
	ip_hdr.ip_len = htons(ip_len);             /* total length */
	ip_hdr.ip_id = htons(id);                 /* IP ID */
	ip_hdr.ip_off = htons(frag);               /* fragmentation flags */
	ip_hdr.ip_ttl = ttl;                       /* time to live */
	ip_hdr.ip_p = prot;                      /* transport protocol */
	ip_hdr.ip_sum = (sum ? htons(sum) : 0);    /* checksum */
	ip_hdr.ip_src.s_addr = src;                       /* source ip */
	ip_hdr.ip_dst.s_addr = dst;                       /* destination ip */

	n = libnet_pblock_append(l, p, (uint8_t *)&ip_hdr, LIBNET_IPV4_H);
	if (n == -1)
	{
		goto bad;
	}

	/* save the original ptag value */
	ptag_hold = ptag;

	if (ptag == LIBNET_PTAG_INITIALIZER)
	{
		ptag = libnet_pblock_update(l, p, LIBNET_IPV4_H, LIBNET_PBLOCK_IPV4_H);
	}

	/* find and set the appropriate ptag, or else use the default of 0 */
	/* When updating the ipv4 block, we need to find the data block, and
	 * adjust our ip_offset if the new payload size is different from what
	 * it used to be.
	 */
	if (ptag_hold && p->prev)
	{
		p_temp = p->prev;
		while (p_temp->prev &&
			(p_temp->type != LIBNET_PBLOCK_IPDATA) &&
			(p_temp->type != LIBNET_PBLOCK_IPV4_H))
		{
			p_temp = p_temp->prev;
		}

		if (p_temp->type == LIBNET_PBLOCK_IPDATA)
		{
			ptag_data = p_temp->ptag;
		}
		else
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): IPv4 data pblock not found", __func__);
		}
	}

	if (payload_s && !payload)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): payload inconsistency", __func__);
		goto bad;
	}

	if (payload_s)
	{
		/* update ptag_data with the new payload */
		/* on create:
		 *    b_len = payload_s
		 *    l->total_size += b_len
		 *    h_len = 0
		 * on update:
		 *    b_len = payload_s
		 *    h_len += <diff in size between new b_len and old b_len>
		 *      increments if if b_len goes up, down if it goes down
		 * in either case:
		 *    copied = 0
	 */
		p_data = libnet_pblock_probe(l, ptag_data, payload_s,
			LIBNET_PBLOCK_IPDATA);
		if (p_data == NULL)
		{
			return (-1);
		}

		if (libnet_pblock_append(l, p_data, payload, payload_s) == -1)
		{
			goto bad;
		}

		if (ptag_data == LIBNET_PTAG_INITIALIZER)
		{
			/* IPDATA's h_len gets set to payload_s in both branches */
			if (p_data->prev->type == LIBNET_PBLOCK_IPV4_H)
			{
				libnet_pblock_update(l, p_data, payload_s,
					LIBNET_PBLOCK_IPDATA);
				/* swap pblocks to correct the protocol order */
				libnet_pblock_swap(l, p->ptag, p_data->ptag);
			}
			else
			{
				/* SR - I'm not sure how to reach this code. Maybe if the first
				 * time we added an ipv4 block, there was no payload, but when
				 * we modify the block the next time, we have payload?
		 */

		 /* update without setting this as the final pblock */
				p_data->type = LIBNET_PBLOCK_IPDATA;
				p_data->ptag = ++(l->ptag_state);
				p_data->h_len = payload_s; /* TODO dead code, data blocks don't have headers */

				/* data was added after the initial construction */
				for (p_temp = l->protocol_blocks;
					p_temp->type == LIBNET_PBLOCK_IPV4_H ||
					p_temp->type == LIBNET_PBLOCK_IPO_H;
					p_temp = p_temp->next)
				{
					libnet_pblock_insert_before(l, p_temp->ptag, p_data->ptag);
					break;
				}

				/* the end block needs to have its next pointer cleared */
				l->pblock_end->next = NULL;
			}

			if (p_data->prev && p_data->prev->type == LIBNET_PBLOCK_IPO_H)
			{
				libnet_pblock_swap(l, p_data->prev->ptag, p_data->ptag);
			}
		}
	}
	else
	{
		p_data = libnet_pblock_find(l, ptag_data);
		if (p_data)
		{
			libnet_pblock_delete(l, p_data);
		}
		else
		{
			/*
			 * XXX - When this completes successfully, libnet errbuf contains
			 * an error message so to come correct, we'll clear it.
			 */
			memset(l->err_buf, 0, sizeof(l->err_buf));
		}
	}
	if (sum == 0)
	{
		/*
		 *  If checksum is zero, by default libnet will compute a checksum
		 *  for the user.  The programmer can override this by calling
		 *  libnet_toggle_checksum(l, ptag, 1);
		 */
		libnet_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
	}

	return (ptag);
bad:
	libnet_pblock_delete(l, p);
	return (-1);
}




int Libnet::libnet_finish_setup_socket(libnet_t *l)
{
	BOOL n = TRUE;
	int *nptr = (int*)&n;
	int len;

#ifdef SO_SNDBUF
	len = sizeof(n);
	if (getsockopt(l->fd, SOL_SOCKET, SO_SNDBUF, (char*)&n, &len) < 0)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			" get SO_SNDBUF failed: %s",strerror(errno));
		goto bad;
	}

	for (n += 128; n < 1048576; n += 128)
	{
		if (setsockopt(l->fd, SOL_SOCKET, SO_SNDBUF, (char*)&n, len) < 0)
		{
			if (errno == ENOBUFS)
			{
				break;
			}
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"set SO_SNDBUF failed: %s", strerror(errno));
			goto bad;
		}
	}
#endif

#ifdef SO_BROADCAST
	if (setsockopt(l->fd, SOL_SOCKET, SO_BROADCAST, (char*)nptr, sizeof(n)) == -1)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"set SO_BROADCAST failed: %s",strerror(errno));
		goto bad;
	}
#endif 

	return 0;

bad:
	return (-1);
}

libnet_pblock_t *Libnet::libnet_pblock_find(libnet_t *l, libnet_ptag_t ptag)
{
	libnet_pblock_t *p;

	for (p = l->protocol_blocks; p; p = p->next)
	{
		if (p->ptag == ptag)
		{
			return (p);
		}
	}
	snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
		"%s(): couldn't find protocol block", __func__);
	return (NULL);
}
libnet_pblock_t *Libnet::libnet_pblock_probe(libnet_t *l, libnet_ptag_t ptag, uint32_t b_len, uint8_t type)
{
	int offset;
	libnet_pblock_t *p;

	if (ptag == LIBNET_PTAG_INITIALIZER)
	{
		return libnet_pblock_new(l, b_len);
	}

	/*
	 *  Update this pblock, don't create a new one.  Note that if the
	 *  new packet size is larger than the old one we will do a malloc.
	 */
	p = libnet_pblock_find(l, ptag);

	if (p == NULL)
	{
		/* err msg set in libnet_pblock_find() */
		return (NULL);
	}
	if (p->type != type)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): ptag refers to different type than expected (0x%x != 0x%x)",
			__func__, p->type, type);
		return (NULL);
	}
	/*
	 *  If size is greater than the original block of memory, we need
	 *  to malloc more memory.  Should we use realloc?
	 */
	if (b_len > p->b_len)
	{
		offset = b_len - p->b_len;  /* how many bytes larger new pblock is */
		free(p->buf);
		p->buf = (u_int8_t*)malloc(b_len);
		if (p->buf == NULL)
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): can't resize pblock buffer: %s", __func__,
				strerror(errno));
			return (NULL);
		}
		memset(p->buf, 0, b_len);
		p->h_len += offset; /* new length for checksums */
		p->b_len = b_len;       /* new buf len */
		l->total_size += offset;
	}
	else
	{
		offset = p->b_len - b_len;
		p->h_len -= offset; /* new length for checksums */
		p->b_len = b_len;       /* new buf len */
		l->total_size -= offset;
	}
	p->copied = 0;      /* reset copied counter */

	return (p);
}
void* Libnet::zmalloc(libnet_t* l, uint32_t size, const char* func)
{
	void* v = malloc(size);
	if (v)
		memset(v, 0, size);
	else
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): malloc(): %s", func,
			strerror(errno));
	return v;
}
libnet_pblock_t *Libnet::libnet_pblock_new(libnet_t *l, uint32_t b_len)
{
	libnet_pblock_t *p = (libnet_pblock_t*)zmalloc(l, sizeof(libnet_pblock_t), __func__);
	if (!p)
		return NULL;

	p->buf = (u_int8_t*)zmalloc(l, b_len, __func__);

	if (!p->buf)
	{
		free(p);
		return NULL;
	}

	p->b_len = b_len;

	l->total_size += b_len;
	l->n_pblocks++;

	/* make the head node if it doesn't exist */
	if (l->protocol_blocks == NULL)
	{
		l->protocol_blocks = p;
		l->pblock_end = p;
	}
	else
	{
		l->pblock_end->next = p;
		p->prev = l->pblock_end;
		l->pblock_end = p;
	}

	return p;
}
int Libnet::libnet_pblock_append(libnet_t *l, libnet_pblock_t *p, const void *buf, uint32_t len)
{
	if (len && !buf)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): payload inconsistency", __func__);
		return -1;
	}

	if (p->copied + len > p->b_len)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): memcpy would overflow buffer", __func__);
		return (-1);
	}
	memcpy(p->buf + p->copied, buf, len);
	p->copied += len;
	return (1);
}
libnet_ptag_t Libnet::libnet_pblock_update(libnet_t *l, libnet_pblock_t *p, uint32_t h_len, uint8_t type)
{
	p->type = type;
	p->ptag = ++(l->ptag_state);
	p->h_len = h_len;
	l->pblock_end = p;              /* point end of pblock list here */

	return (p->ptag);
}
void Libnet::libnet_pblock_remove_from_list(libnet_t *l, libnet_pblock_t *p)
{
	if (p->prev)
	{
		p->prev->next = p->next;
	}
	else
	{
		l->protocol_blocks = p->next;
	}

	if (p->next)
	{
		p->next->prev = p->prev;
	}
	else
	{
		l->pblock_end = p->prev;
	}
}
int Libnet::libnet_pblock_insert_before(libnet_t *l, libnet_ptag_t ptag1,libnet_ptag_t ptag2)
{
	libnet_pblock_t *p1, *p2;

	p1 = libnet_pblock_find(l, ptag1);
	p2 = libnet_pblock_find(l, ptag2);
	if (p1 == NULL || p2 == NULL)
	{
		/* error set elsewhere */
		return (-1);
	}

	/* check for already present before */
	if (p2->next == p1)
		return 1;

	libnet_pblock_remove_from_list(l, p2);

	/* insert p2 into list */
	p2->prev = p1->prev;
	p2->next = p1;
	p1->prev = p2;

	if (p2->prev)
	{
		p2->prev->next = p2;
	}
	else
	{
		/* first node on the list */
		l->protocol_blocks = p2;
	}

	return (1);
}
void Libnet::libnet_pblock_delete(libnet_t *l, libnet_pblock_t *p)
{
	if (p)
	{
		l->total_size -= p->b_len;
		l->n_pblocks--;

		libnet_pblock_remove_from_list(l, p);

		if (p->buf)
		{
			free(p->buf);
			p->buf = NULL;
		}

		free(p);
	}
}
void Libnet::libnet_pblock_setflags(libnet_pblock_t *p, uint8_t flags)
{
	p->flags = flags;
}
int Libnet::libnet_pblock_swap(libnet_t *l, libnet_ptag_t ptag1, libnet_ptag_t ptag2)
{
	libnet_pblock_t *p1, *p2;

	p1 = libnet_pblock_find(l, ptag1);
	p2 = libnet_pblock_find(l, ptag2);
	if (p1 == NULL || p2 == NULL)
	{
		/* error set elsewhere */
		return (-1);
	}

	p2->prev = p1->prev;
	p1->next = p2->next;
	p2->next = p1;
	p1->prev = p2;

	if (p1->next)
	{
		p1->next->prev = p1;
	}

	if (p2->prev)
	{
		p2->prev->next = p2;
	}
	else
	{
		/* first node on the list */
		l->protocol_blocks = p2;
	}

	if (l->pblock_end == p2)
	{
		l->pblock_end = p1;
	}
	return (1);
}
BYTE * Libnet::libnet_win32_read_arp_table(DWORD DestIP)
{
	static BYTE buffMAC[6];
	BOOL fOrder = TRUE;
	BYTE *MAC = NULL;
	DWORD status, i, ci;

	PMIB_IPNETTABLE pIpNetTable = NULL;
	DWORD Size = 0;

	memset(buffMAC, 0, sizeof(buffMAC));

	if ((status = GetIpNetTable(pIpNetTable, &Size, fOrder)) == ERROR_INSUFFICIENT_BUFFER)
	{
		pIpNetTable = (PMIB_IPNETTABLE)malloc(Size);
		assert(pIpNetTable);
		status = GetIpNetTable(pIpNetTable, &Size, fOrder);
	}

	if (status == NO_ERROR)
	{
		/* set current interface */
		ci = pIpNetTable->table[0].dwIndex;

		for (i = 0; i < pIpNetTable->dwNumEntries; ++i)
		{
			if (pIpNetTable->table[i].dwIndex != ci)
				ci = pIpNetTable->table[i].dwIndex;

			if (pIpNetTable->table[i].dwAddr == DestIP) /* found IP in arp cache */
			{
				memcpy(buffMAC, pIpNetTable->table[i].bPhysAddr, sizeof(buffMAC));
				free(pIpNetTable);
				return buffMAC;
			}
		}

		if (pIpNetTable)
			free(pIpNetTable);
		return(NULL);
	}
	else
	{
		if (pIpNetTable)
		{
			free(pIpNetTable);
		}
		MAC = NULL;
	}
	return(NULL);
}
BYTE *Libnet::libnet_win32_get_remote_mac(libnet_t *l, DWORD DestIP)
{
	HRESULT hr;
	ULONG   pulMac[6];
	ULONG   ulLen = 6;
	static PBYTE pbHexMac;
	PIP_ADAPTER_INFO pinfo = NULL;
	DWORD dwSize = 0;
	struct sockaddr_in sin;
	static BYTE bcastmac[] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

	BYTE *MAC = libnet_win32_read_arp_table(DestIP);

	if (MAC == NULL)
	{
		memset(pulMac, 0xff, sizeof(pulMac));
		memset(&sin, 0, sizeof(sin));

		if ((hr = SendARP(DestIP, 0, pulMac, &ulLen)) != NO_ERROR)
		{
			*(int32_t *)&sin.sin_addr = DestIP;
			GetAdaptersInfo(NULL, &dwSize);
			pinfo = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR, dwSize);
			GetAdaptersInfo(pinfo, &dwSize);
			if (pinfo != NULL)
			{
				DestIP = inet_addr(pinfo->GatewayList.IpAddress.String);
				memset(pulMac, 0xff, sizeof(pulMac));
				ulLen = 6;
				if ((hr = SendARP(DestIP, 0, pulMac, &ulLen)) != NO_ERROR)
				{
					GlobalFree(pinfo);
					return(bcastmac);
				}
			}
			else
			{
				GlobalFree(pinfo);
				return(bcastmac); /* ff:ff:ff:ff:ff:ff */
			}
		}

		pbHexMac = (PBYTE)pulMac;

		return (pbHexMac);
	}
	else
	{
		return (MAC);
	}
}
uint32_t Libnet::libnet_get_ipaddr4(libnet_t *l)
{
	long npflen = 0;
	struct sockaddr_in sin;
	struct npf_if_addr ipbuff;

	memset(&sin, 0, sizeof(sin));
	memset(&ipbuff, 0, sizeof(ipbuff));

	npflen = sizeof(ipbuff);
	if (PacketGetNetInfoEx(l->device, &ipbuff, &npflen))
	{
		sin = *(struct sockaddr_in *)&ipbuff.IPAddress;
	}
	return (sin.sin_addr.s_addr);
}
int Libnet::libnet_in_cksum(uint16_t * addr, int len)
{
	int sum;
#ifdef DEBIAN
	uint16_t last_byte;

	sum = 0;
	last_byte = 0;
#else
	union
	{
		uint16_t s;
		uint8_t b[2];
}pad;

	sum = 0;
#endif

	while (len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
#ifdef DEBIAN
	if (len == 1)
	{
		*(uint8_t *)&last_byte = *(uint8_t *)addr;
		sum += last_byte;
#else
	if (len == 1)
	{
		pad.b[0] = *(uint8_t *)addr;
		pad.b[1] = 0;
		sum += pad.s;
#endif
	}

	return (sum);
}
int Libnet::libnet_pblock_coalesce(libnet_t *l, uint8_t **packet, uint32_t *size)
{
	/*
	 *  Determine the offset required to keep memory aligned (strict
	 *  architectures like solaris enforce this, but's a good practice
	 *  either way).  This is only required on the link layer with the
	 *  14 byte ethernet offset (others are similarly unkind).
	 */
	if (l->injection_type == LIBNET_LINK ||
		l->injection_type == LIBNET_LINK_ADV)
	{
		/* 8 byte alignment should work */
		l->aligner = 8 - (l->link_offset % 8);
	}
	else
	{
		l->aligner = 0;
	}

	if (!l->total_size && !l->aligner) {
		/* Avoid allocating zero bytes of memory, it perturbs electric fence. */
		*packet = (uint8_t*)malloc(1);
		**packet = 1;
	}
	else {
		*packet = (uint8_t*)malloc(l->aligner + l->total_size);
	}
	if (*packet == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): malloc(): %s",
			__func__, strerror(errno));
		return (-1);
	}

	memset(*packet, 0, l->aligner + l->total_size);

	if (l->injection_type == LIBNET_RAW4 &&
		l->pblock_end->type == LIBNET_PBLOCK_IPV4_H)
	{
		libnet_pblock_setflags(l->pblock_end, LIBNET_PBLOCK_DO_CHECKSUM);
	}

	/* additional sanity checks to perform if we're not in advanced mode */
	if (!(l->injection_type & LIBNET_ADV_MASK))
	{
		switch (l->injection_type)
		{
		case LIBNET_LINK:
			if ((l->pblock_end->type != LIBNET_PBLOCK_TOKEN_RING_H) &&
				(l->pblock_end->type != LIBNET_PBLOCK_FDDI_H) &&
				(l->pblock_end->type != LIBNET_PBLOCK_ETH_H) &&
				(l->pblock_end->type != LIBNET_PBLOCK_802_1Q_H) &&
				(l->pblock_end->type != LIBNET_PBLOCK_ISL_H) &&
				(l->pblock_end->type != LIBNET_PBLOCK_802_3_H))
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): packet assembly cannot find a layer 2 header",
					__func__);
				goto err;
			}
			break;
		case LIBNET_RAW4:
			if ((l->pblock_end->type != LIBNET_PBLOCK_IPV4_H))
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): packet assembly cannot find an IPv4 header",
					__func__);
				goto err;
			}
			break;
		case LIBNET_RAW6:
			if ((l->pblock_end->type != LIBNET_PBLOCK_IPV6_H))
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): packet assembly cannot find an IPv6 header",
					__func__);
				goto err;
			}
			break;
		default:
			/* we should not end up here ever */
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): suddenly the dungeon collapses -- you die",
				__func__);
			goto err;
			break;
		}
	}

	/* Build packet from end to start. */
	{
		/*
		   From top to bottom, go through pblocks pairwise:

		   p   is the currently being copied pblock, and steps through every block
		   q   is the prev pblock to p that needs checksumming, it will
			   not step through every block as p does, it will skip any that do not
			   need checksumming.
		   n   offset from start of packet to beginning of block we are writing

		   q is NULL on first iteration
		   p is NULL on last iteration

		   Checksums are done on q, to give p a chance to be copied over, since
		   checksumming q can require a lower-level header to be encoded, in the
		   case of IP protocols (which are the only kinds handled by libnet's
		   checksum implementation).

		   This is very obscure, or would be much more clear if it was done in
		   two loops.
		   */
		libnet_pblock_t *q = NULL;
		libnet_pblock_t *p = NULL;
		uint32_t n;

		for (n = l->aligner + l->total_size, p = l->protocol_blocks; p || q; )
		{
			if (q)
			{
				p = p->next;
			}
			if (p)
			{
				n -= p->b_len;
				/* copy over the packet chunk */
				memcpy(*packet + n, p->buf, p->b_len);
			}
#if 0
			printf("-- n %d/%d cksum? %d\n", n, l->aligner + l->total_size,
				q &&
				(p == NULL || (p->flags & LIBNET_PBLOCK_DO_CHECKSUM)) &&
				(q->flags & LIBNET_PBLOCK_DO_CHECKSUM));
			if (q)
			{
				printf(" iph %d/%d offset -%d\n",
					(l->total_size + l->aligner) - q->ip_offset,
					l->total_size + l->aligner,
					q->ip_offset
				);
			}
			if (p)
			{
				printf("p %p ptag %d b_len %d h_len %d cksum? %d type %s\n",
					p, p->ptag,
					p->b_len, p->h_len,
					p->flags & LIBNET_PBLOCK_DO_CHECKSUM,
					libnet_diag_dump_pblock_type(p->type)
				);
			}
			if (q)
			{
				printf("q %p ptag %d b_len %d h_len %d cksum? %d type %s\n",
					q, q->ptag,
					q->b_len, q->h_len,
					q->flags & LIBNET_PBLOCK_DO_CHECKSUM,
					libnet_diag_dump_pblock_type(q->type)
				);
			}
#endif
			if (q)
			{
				if (p == NULL || (p->flags & LIBNET_PBLOCK_DO_CHECKSUM))
				{
					if (q->flags & LIBNET_PBLOCK_DO_CHECKSUM)
					{
						uint32_t c;
						uint8_t* end = *packet + l->aligner + l->total_size;
						uint8_t* beg = *packet + n;
						int ip_offset = calculate_ip_offset(l, q);
						uint8_t* iph = end - ip_offset;
#if 0
						printf("p %d/%s q %d/%s offset calculated %d\n",
							p ? p->ptag : -1, p ? libnet_diag_dump_pblock_type(p->type) : "nil",
							q->ptag, libnet_diag_dump_pblock_type(q->type),
							ip_offset);
#endif
						c = libnet_inet_checksum(l, iph,
							libnet_pblock_p2p(q->type), q->h_len,
							beg, end);
						if (c == -1)
						{
							/* err msg set in libnet_do_checksum() */
							goto err;
						}
					}
					q = p;
				}
			}
			else
			{
				q = p;
			}
		}
	}
	*size = l->aligner + l->total_size;

	/*
	 *  Set the packet pointer to the true beginning of the packet and set
	 *  the size for transmission.
	 */
	if ((l->injection_type == LIBNET_LINK ||
		l->injection_type == LIBNET_LINK_ADV) && l->aligner)
	{
		*packet += l->aligner;
		*size -= l->aligner;
	}
	return (1);

err:
	free(*packet);
	*packet = NULL;
	return (-1);
}
int Libnet::libnet_pblock_p2p(uint8_t type)
{
	/* for checksum; return the protocol number given a pblock type*/
	switch (type)
	{
	case LIBNET_PBLOCK_CDP_H:
		return (LIBNET_PROTO_CDP);
	case LIBNET_PBLOCK_ICMPV4_H:
	case LIBNET_PBLOCK_ICMPV4_ECHO_H:
	case LIBNET_PBLOCK_ICMPV4_MASK_H:
	case LIBNET_PBLOCK_ICMPV4_UNREACH_H:
	case LIBNET_PBLOCK_ICMPV4_TIMXCEED_H:
	case LIBNET_PBLOCK_ICMPV4_REDIRECT_H:
	case LIBNET_PBLOCK_ICMPV4_TS_H:
		return (IPPROTO_ICMP);
	case LIBNET_PBLOCK_ICMPV6_H:
	case LIBNET_PBLOCK_ICMPV6_ECHO_H:
	case LIBNET_PBLOCK_ICMPV6_UNREACH_H:
	case LIBNET_PBLOCK_ICMPV6_NDP_NSOL_H:
	case LIBNET_PBLOCK_ICMPV6_NDP_NADV_H:
		return (IPPROTO_ICMPV6);
	case LIBNET_PBLOCK_IGMP_H:
		return (IPPROTO_IGMP);
	case LIBNET_PBLOCK_IPV4_H:
		return (IPPROTO_IP);
	case LIBNET_PBLOCK_IPV6_H:
		return (IPPROTO_IPV6);
	case LIBNET_ISL_H:
		return (LIBNET_PROTO_ISL);
	case LIBNET_PBLOCK_OSPF_H:
		return (IPPROTO_OSPF);
	case LIBNET_PBLOCK_LS_RTR_H:
		return (IPPROTO_OSPF_LSA);
	case LIBNET_PBLOCK_TCP_H:
		return (IPPROTO_TCP);
	case LIBNET_PBLOCK_UDP_H:
		return (IPPROTO_UDP);
	case LIBNET_PBLOCK_VRRP_H:
		return (IPPROTO_VRRP);
	case LIBNET_PBLOCK_GRE_H:
		return (IPPROTO_GRE);
	default:
		return (-1);
	}
}
int Libnet::calculate_ip_offset(libnet_t* l, libnet_pblock_t* q)
{
	int ip_offset = 0;
	libnet_pblock_t* p = l->protocol_blocks;
	for (; p && p != q; p = p->next) {
		ip_offset += p->b_len;
	}
	assert(p == q); /* if not true, then q is not a pblock! */

	for (; p; p = p->next) {
		ip_offset += p->b_len;
		if (pblock_is_ip(p))
			break;
	}

	return ip_offset;
}
int Libnet::pblock_is_ip(libnet_pblock_t* p)
{
	return p->type == LIBNET_PBLOCK_IPV4_H || p->type == LIBNET_PBLOCK_IPV6_H;
}
int Libnet::libnet_inet_checksum(libnet_t *l, uint8_t *iphdr, int protocol, int h_len, const uint8_t *beg, const uint8_t * end)
{
	/* will need to update this for ipv6 at some point */
	struct libnet_ipv4_hdr *iph_p = (struct libnet_ipv4_hdr *)iphdr;
	struct libnet_ipv6_hdr *ip6h_p = NULL; /* default to not using IPv6 */
	int ip_hl = 0;
	int sum = 0;

	/* Check for memory under/over reads/writes. */
	if (iphdr < beg || (iphdr + sizeof(*iph_p)) > end)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): ipv4 hdr not inside packet (where %d, size %d)", __func__,
			(int)(iphdr - beg), (int)(end - beg));
		return -1;
	}

	/*
	 *  Figure out which IP version we're dealing with.  We'll assume v4
	 *  and overlay a header structure to yank out the version.
	 */
	if (iph_p->ip_v == 6)
	{
		ip6h_p = (struct libnet_ipv6_hdr *)iph_p;
		iph_p = NULL;
		ip_hl = 40;
		uint8_t ip_nh = ip6h_p->ip_nh;

		if ((uint8_t*)(ip6h_p + 1) > end)
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): ipv6 hdr not inside packet", __func__);
			return -1;
		}

		/* FIXME this entire fragile exercise would be avoided if we just passed
		 * in the pointer to the protocol block 'q' we are checksumming, which
		 * we know.
		 */
		while (ip_nh != protocol && (uint8_t*)ip6h_p + ip_hl + 1 < end)
		{
			/* next header is not the upper layer protocol */
			switch (ip_nh)
			{
			case IPPROTO_DSTOPTS:
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_FRAGMENT:
			case IPPROTO_AH:
			case IPPROTO_ESP:
			case IPPROTO_MH:
				/*
				 * count option headers to the header length for
				 * checksum processing
				 */
				 /* Common structure of ipv6 ext headers is:
				  *  uint8: next header protocol
				  *  uint8: length of this header, in multiples of 8, not
				  *    including first eight octets
				  * The pointer arithmetic below follows from above.
				  */
				ip_nh = *((uint8_t*)ip6h_p + ip_hl); /* next next header */
				ip_hl += (*((uint8_t*)ip6h_p + ip_hl + 1) + 1) * 8; /* ext header length */
				break;
			default:
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): unsupported extension header (%d)", __func__, ip_nh);
				return -1;
			}

		}
	}
	else
	{
		ip_hl = iph_p->ip_hl << 2;
	}

	if ((iphdr + ip_hl) > end)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): ip hdr len not inside packet", __func__);
		return -1;
	}

	/*
	 *  Dug Song came up with this very cool checksuming implementation
	 *  eliminating the need for explicit psuedoheader use.  Check it out.
	 */
	switch (protocol)
	{
	case IPPROTO_TCP:
	{
		struct libnet_tcp_hdr *tcph_p =
			(struct libnet_tcp_hdr *)(iphdr + ip_hl);

		h_len = (int)(end - (uint8_t*)tcph_p); /* ignore h_len, sum the packet we've coalesced */

		CHECK_IP_PAYLOAD_SIZE();

#if (STUPID_SOLARIS_CHECKSUM_BUG)
		tcph_p->th_sum = tcph_p->th_off << 2;
		return (1);
#endif /* STUPID_SOLARIS_CHECKSUM_BUG */
#if (HAVE_HPUX11)   
		if (l->injection_type != LIBNET_LINK)
		{
			/*
			 *  Similiar to the Solaris Checksum bug - but need to add
			 *  the size of the TCP payload (only for raw sockets).
			 */
			tcph_p->th_sum = (tcph_p->th_off << 2) +
				(h_len - (tcph_p->th_off << 2));
			return (1);
		}
#endif
		/* TCP checksum is over the IP pseudo header:
		 * ip src
		 * ip dst
		 * tcp protocol (IPPROTO_TCP)
		 * tcp length, including the header
		 * + the TCP header (with checksum set to zero) and data
		 */
		tcph_p->th_sum = 0;
		if (ip6h_p)
		{
			sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
		}
		else
		{
			/* 8 = src and dst */
			sum = libnet_in_cksum((uint16_t *)&iph_p->ip_src, 8);
		}
		sum += ntohs(IPPROTO_TCP + h_len);
		sum += libnet_in_cksum((uint16_t *)tcph_p, h_len);
		tcph_p->th_sum = LIBNET_CKSUM_CARRY(sum);
#if 0
		printf("tcp sum calculated: %#x/%d h_len %d\n",
			ntohs(tcph_p->th_sum),
			ntohs(tcph_p->th_sum),
			h_len
		);
#endif
		break;
	}
	case IPPROTO_UDP:
	{
		struct libnet_udp_hdr *udph_p =
			(struct libnet_udp_hdr *)(iphdr + ip_hl);

		h_len = (int)(end - (uint8_t*)udph_p); /* ignore h_len, sum the packet we've coalesced */

		CHECK_IP_PAYLOAD_SIZE();

		udph_p->uh_sum = 0;
		if (ip6h_p)
		{
			sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
		}
		else
		{
			sum = libnet_in_cksum((uint16_t *)&iph_p->ip_src, 8);
		}
		sum += ntohs(IPPROTO_UDP + h_len);
		sum += libnet_in_cksum((uint16_t *)udph_p, h_len);
		udph_p->uh_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case IPPROTO_ICMP:
	{
		struct libnet_icmpv4_hdr *icmph_p =
			(struct libnet_icmpv4_hdr *)(iphdr + ip_hl);

		h_len = (int)(end - (uint8_t*)icmph_p); /* ignore h_len, sum the packet we've coalesced */

		CHECK_IP_PAYLOAD_SIZE();

		icmph_p->icmp_sum = 0;
		/* Hm, is this valid? Is the checksum algorithm for ICMPv6 encapsulated in IPv4
		 * actually defined?
		 */
		if (ip6h_p)
		{
			sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
			sum += ntohs(IPPROTO_ICMP6 + h_len);
		}
		sum += libnet_in_cksum((uint16_t *)icmph_p, h_len);
		icmph_p->icmp_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case IPPROTO_ICMPV6:
	{
		struct libnet_icmpv6_hdr *icmph_p =
			(struct libnet_icmpv6_hdr *)(iphdr + ip_hl);

		h_len = (int)(end - (uint8_t*)icmph_p); /* ignore h_len, sum the packet we've coalesced */

		CHECK_IP_PAYLOAD_SIZE();

		icmph_p->icmp_sum = 0;
		if (ip6h_p)
		{
			sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
			sum += ntohs(IPPROTO_ICMP6 + h_len);
		}
		sum += libnet_in_cksum((uint16_t *)icmph_p, h_len);
		icmph_p->icmp_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case IPPROTO_IGMP:
	{
		struct libnet_igmp_hdr *igmph_p =
			(struct libnet_igmp_hdr *)(iphdr + ip_hl);

		h_len = (int)(end - (uint8_t*)igmph_p); /* ignore h_len, sum the packet we've coalesced */

		CHECK_IP_PAYLOAD_SIZE();

		igmph_p->igmp_sum = 0;
		sum = libnet_in_cksum((uint16_t *)igmph_p, h_len);
		igmph_p->igmp_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case IPPROTO_GRE:
	{
		/* checksum is always at the same place in GRE header
		 * in the multiple RFC version of the protocol ... ouf !!!
		 */
		struct libnet_gre_hdr *greh_p =
			(struct libnet_gre_hdr *)(iphdr + ip_hl);
		uint16_t fv = ntohs(greh_p->flags_ver);

		CHECK_IP_PAYLOAD_SIZE();

		if (!(fv & (GRE_CSUM | GRE_ROUTING | GRE_VERSION_0)) ||
			!(fv & (GRE_CSUM | GRE_VERSION_1)))
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): can't compute GRE checksum (wrong flags_ver bits: 0x%x )", __func__, fv);
			return (-1);
		}
		sum = libnet_in_cksum((uint16_t *)greh_p, h_len);
		greh_p->gre_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case IPPROTO_OSPF:
	{
		struct libnet_ospf_hdr *oh_p =
			(struct libnet_ospf_hdr *)(iphdr + ip_hl);

		CHECK_IP_PAYLOAD_SIZE();

		oh_p->ospf_sum = 0;
		sum += libnet_in_cksum((uint16_t *)oh_p, h_len);
		oh_p->ospf_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case IPPROTO_OSPF_LSA:
	{
		struct libnet_ospf_hdr *oh_p =
			(struct libnet_ospf_hdr *)(iphdr + ip_hl);
		struct libnet_lsa_hdr *lsa_p =
			(struct libnet_lsa_hdr *)(iphdr +
				ip_hl + oh_p->ospf_len);

		/* FIXME need additional length check, to account for ospf_len */
		lsa_p->lsa_sum = 0;
		sum += libnet_in_cksum((uint16_t *)lsa_p, h_len);
		lsa_p->lsa_sum = LIBNET_CKSUM_CARRY(sum);
		break;
#if 0
		/*
		 *  Reworked fletcher checksum taken from RFC 1008.
		 */
		int c0, c1;
		struct libnet_lsa_hdr *lsa_p = (struct libnet_lsa_hdr *)buf;
		uint8_t *p, *p1, *p2, *p3;

		c0 = 0;
		c1 = 0;

		lsa_p->lsa_cksum = 0;

		p = buf;
		p1 = buf;
		p3 = buf + len;             /* beginning and end of buf */

		while (p1 < p3)
		{
			p2 = p1 + LIBNET_MODX;
			if (p2 > p3)
			{
				p2 = p3;
			}

			for (p = p1; p < p2; p++)
			{
				c0 += (*p);
				c1 += c0;
			}

			c0 %= 255;
			c1 %= 255;      /* modular 255 */

			p1 = p2;
		}

#if AWR_PLEASE_REWORK_THIS
		lsa_p->lsa_cksum[0] = (((len - 17) * c0 - c1) % 255);
		if (lsa_p->lsa_cksum[0] <= 0)
		{
			lsa_p->lsa_cksum[0] += 255;
		}

		lsa_p->lsa_cksum[1] = (510 - c0 - lsa_p->lsa_cksum[0]);
		if (lsa_p->lsa_cksum[1] > 255)
		{
			lsa_p->lsa_cksum[1] -= 255;
		}
#endif
		break;
#endif
	}
	case IPPROTO_IP:
	{
		if (!iph_p) {
			/* IPv6 doesn't have a checksum */
		}
		else {
			iph_p->ip_sum = 0;
			sum = libnet_in_cksum((uint16_t *)iph_p, ip_hl);
			iph_p->ip_sum = LIBNET_CKSUM_CARRY(sum);
		}
		break;
	}
	case IPPROTO_VRRP:
	{
		struct libnet_vrrp_hdr *vrrph_p =
			(struct libnet_vrrp_hdr *)(iphdr + ip_hl);
		CHECK_IP_PAYLOAD_SIZE();

		vrrph_p->vrrp_sum = 0;
		sum = libnet_in_cksum((uint16_t *)vrrph_p, h_len);
		vrrph_p->vrrp_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case LIBNET_PROTO_CDP:
	{   /* XXX - Broken: how can we easily get the entire packet size? */
	/* FIXME you can't, checksumming non-IP protocols was not supported by libnet */
		struct libnet_cdp_hdr *cdph_p =
			(struct libnet_cdp_hdr *)iphdr;

		if ((iphdr + h_len) > end)
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): cdp payload not inside packet", __func__);
			return -1;
		}

		cdph_p->cdp_sum = 0;
		sum = libnet_in_cksum((uint16_t *)cdph_p, h_len);
		cdph_p->cdp_sum = LIBNET_CKSUM_CARRY(sum);
		break;
	}
	case LIBNET_PROTO_ISL:
	{
#if 0
		struct libnet_isl_hdr *islh_p =
			(struct libnet_isl_hdr *)buf;
#endif
		/*
		 *  Need to compute 4 byte CRC for the ethernet frame and for
		 *  the ISL frame itself.  Use the libnet_crc function.
		 */
	}
	default:
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): unsupported protocol %d", __func__, protocol);
		return (-1);
	}
	}
	return (1);
}
int Libnet::libnet_write_raw_ipv4(libnet_t *l, const uint8_t *packet, uint32_t size)
{
	return (libnet_win32_write_raw_ipv4(l, packet, size));
}
int Libnet::libnet_win32_write_raw_ipv4(libnet_t *l, const uint8_t *payload, uint32_t payload_s)
{
	static BYTE dst[ETHER_ADDR_LEN];
	static BYTE src[ETHER_ADDR_LEN];

	uint8_t *packet = NULL;
	uint32_t packet_s;

	LPPACKET lpPacket = NULL;
	DWORD remoteip = 0;
	DWORD BytesTransfered;
	NetType type;
	struct libnet_ipv4_hdr *ip_hdr = NULL;

	memset(dst, 0, sizeof(dst));
	memset(src, 0, sizeof(src));

	packet_s = payload_s + l->link_offset;
	packet = (uint8_t *)malloc(packet_s);
	if (packet == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): failed to allocate packet", __func__);
		return (-1);
	}
	/* FIXME all the return paths below, except the last, leak 'packet' */

	/* we have to do the IP checksum  */
	/* FIXME MSVC warning is correct, checksum modifies its input. Fix is to build checksum inside the allocated 'packet' */
	if (libnet_inet_checksum(l, (uint8_t*)payload, IPPROTO_IP, LIBNET_IPV4_H, payload, payload + payload_s) == -1)
	{
		/* error msg set in libnet_do_checksum */
		return (-1);
	}

	/* MACs, IPs and other stuff... */
	ip_hdr = (struct libnet_ipv4_hdr *)payload;
	memcpy(src, libnet_get_hwaddr(l), sizeof(src));
	remoteip = ip_hdr->ip_dst.S_un.S_addr;

	/* check if the remote station is the local station */
	//printf("www.baidu.com ip = %s\n", inet_ntoa(*((struct in_addr*)&dstip)));
	if (remoteip == libnet_get_ipaddr4(l))
	{
		memcpy(dst, src, sizeof(dst));
	}
	else
	{
		memcpy(dst, libnet_win32_get_remote_mac(l, remoteip), sizeof(dst));
	}

	
	PacketGetNetType(l->lpAdapter, &type);

	switch (type.LinkType)
	{
	case NdisMedium802_3:
		libnet_win32_build_fake_ethernet(dst, src, ETHERTYPE_IP, payload,
			payload_s, packet, l, 0);
		break;
	case NdisMedium802_5:
		libnet_win32_build_fake_token(dst, src, ETHERTYPE_IP, payload,
			payload_s, packet, l, 0);
		break;
	case NdisMediumFddi:
		break;
	case NdisMediumWan:
	case NdisMediumAtm:
	case NdisMediumArcnet878_2:
	default:
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): network type (%d) is not supported", __func__,
			type.LinkType);
		return (-1);
		break;
	}

	BytesTransfered = -1;
	if ((lpPacket = PacketAllocatePacket()) == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): failed to allocate the LPPACKET structure", __func__);
		return (-1);
	}

	PacketInitPacket(lpPacket, packet, packet_s);

	/* PacketSendPacket returns a BOOLEAN */
	if (PacketSendPacket(l->lpAdapter, lpPacket, TRUE))
	{
		BytesTransfered = packet_s;
	}

	PacketFreePacket(lpPacket);
	free(packet);

	return (BytesTransfered);
}
struct libnet_ether_addr * Libnet::libnet_get_hwaddr(libnet_t *l)
{
	/* This implementation is not-reentrant. */
	static struct libnet_ether_addr *mac;

	ULONG IoCtlBufferLength = (sizeof(PACKET_OID_DATA) + sizeof(ULONG) - 1);
	PPACKET_OID_DATA OidData;

	int i = 0;

	if (l == NULL)
	{
		return (NULL);
	}

	if (l->device == NULL)
	{
		if (libnet_select_device(l) == -1)
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): can't figure out a device to use", __func__);
			return (NULL);
		}
	}

	mac = (struct libnet_ether_addr *)calloc(1, sizeof(struct libnet_ether_addr));
	if (mac == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): calloc error", __func__);
		return (NULL);
	}

	OidData = (struct _PACKET_OID_DATA *) malloc(IoCtlBufferLength);

	if (OidData == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): OidData is NULL", __func__);
		return(NULL);
	}

	if (l->link_type == DLT_IEEE802)
	{
		OidData->Oid = OID_802_5_CURRENT_ADDRESS;
	}
	else
	{
		OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	}

	OidData->Length = 6;
	if ((PacketRequest(l->lpAdapter, FALSE, OidData)) == FALSE)
	{
		memset(mac, 0, 6);
	}
	else
	{
		for (i = 0; i < 6; i++)
		{
			mac->ether_addr_octet[i] = OidData->Data[i];
		}
	}
	free(OidData);
	return(mac);
}
int Libnet::libnet_select_device(libnet_t *l)
{
	int c, i;
	struct libnet_ifaddr_list *address_list, *al;
	uint32_t addr;


	if (l == NULL)
	{
		return (-1);
	}

	if (l->device && !isdigit(l->device[0]))
	{
#if !(__WIN32__)
		if (libnet_check_iface(l) < 0)
		{
			/* err msg set in libnet_check_iface() */
			return (-1);
		}
#endif
		return (1);
	}

	/*
	 *  Number of interfaces.
	 */
	c = libnet_ifaddrlist(&address_list, l->device, l->err_buf);
	if (c < 0)
	{
		return (-1);
	}
	else if (c == 0)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): no network interface found", __func__);
		return (-1);
	}

	al = address_list;
	if (l->device)
	{
		addr = libnet_name2addr4(l, l->device, LIBNET_DONT_RESOLVE);

		for (i = c; i; --i, ++address_list)
		{
			if (
				0 == strcmp(l->device, address_list->device)
				||
				address_list->addr == addr
				)
			{
				/* free the "user supplied device" - see libnet_init() */
				free(l->device);
				l->device = strdup(address_list->device);
				goto good;
			}
		}
		if (i <= 0)
		{
			snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				"%s(): can't find interface for IP %s", __func__,
				l->device);
			goto bad;
		}
	}
	else
	{
		l->device = strdup(address_list->device);
	}

good:
	for (i = 0; i < c; i++)
	{
		free(al[i].device);
		al[i].device = NULL;
	}
	return (1);

bad:
	for (i = 0; i < c; i++)
	{
		free(al[i].device);
		al[i].device = NULL;
	}
	return (-1);
}
int Libnet::libnet_ifaddrlist(register struct libnet_ifaddr_list **ipaddrp, char *dev_unused, register char *errbuf)
{
	int nipaddr = 0;
	int i = 0;
	static struct libnet_ifaddr_list ifaddrlist[MAX_IPADDR];
	pcap_if_t *devlist = NULL;
	pcap_if_t *dev = NULL;
	int8_t err[PCAP_ERRBUF_SIZE];

	/* Retrieve the interfaces list */
	if (pcap_findalldevs(&devlist, (char*)err) == -1)
	{
		snprintf(errbuf, LIBNET_ERRBUF_SIZE,
			"%s(): error in pcap_findalldevs: %s", __func__, err);
		return (-1);
	}

	for (dev = devlist; dev; dev = dev->next)
	{
		struct pcap_addr* pcapaddr;
		for (pcapaddr = dev->addresses; pcapaddr; pcapaddr = pcapaddr->next) {
			struct sockaddr* addr = pcapaddr->addr;
#if 0
			printf("if name '%s' description '%s' loop? %d\n", dev->name, dev->description, dev->flags);
			{
				char p[NI_MAXHOST] = "";
				int sz = sizeof(struct sockaddr_storage);
				int r;
				r = getnameinfo(addr, sz, p, sizeof(p), NULL, 0, NI_NUMERICHOST);
				printf("  addr %s\n", r ? gai_strerror(r) : p);
			}
#endif

			if (dev->flags & PCAP_IF_LOOPBACK)
				continue;

			/* this code ignores IPv6 addresses, a limitation of the libnet_ifaddr_list struct */

			if (addr->sa_family == AF_INET) {
				ifaddrlist[i].device = strdup(dev->name);
				ifaddrlist[i].addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
				++i;
				++nipaddr;
			}
		}
	}

	pcap_freealldevs(devlist);

	*ipaddrp = ifaddrlist;

	return nipaddr;
}
uint32_t Libnet::libnet_name2addr4(libnet_t *l, char *host_name, uint8_t use_name)
{
	struct in_addr addr;
	struct hostent *host_ent;
	uint32_t m;
	uint32_t val;
	int i;

	if (use_name == LIBNET_RESOLVE)
	{
		if ((addr.s_addr = inet_addr(host_name)) == -1)
		{
			if (!(host_ent = gethostbyname(host_name)))
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): %s", __func__,
#if (_WIN32)
					"gethostbyname failure"
#else
					/* FIXME doesn't exist on windows, needs WSAGetLastError()/FormatMessage */
					hstrerror(h_errno)
#endif
				);
				/* XXX - this is actually 255.255.255.255 */
				return (-1);
			}
			memcpy(&addr.s_addr, host_ent->h_addr, host_ent->h_length);
		}
		/* network byte order */
		return (addr.s_addr);
	}
	else
	{
		/*
		 *  We only want dots 'n decimals.
		 */
		if (!isdigit(host_name[0]))
		{
			if (l)
			{
				snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
					"%s(): expecting dots and decimals", __func__);
			}
			/* XXX - this is actually 255.255.255.255 */
			return (-1);
		}

		m = 0;
		for (i = 0; i < 4; i++)
		{
			m <<= 8;
			if (*host_name)
			{
				val = 0;
				while (*host_name && *host_name != '.')
				{
					val *= 10;
					val += *host_name - '0';
					if (val > 255)
					{
						if (l)
						{
							snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
								"%s(): value greater than 255", __func__);
						}
						/* XXX - this is actually 255.255.255.255 */
						return (-1);
					}
					host_name++;
				}
				m |= val;
				if (*host_name)
				{
					host_name++;
				}
			}
		}
		/* host byte order */
		return (ntohl(m));
	}
}
libnet_ptag_t Libnet::libnet_win32_build_fake_ethernet(uint8_t *dst, uint8_t *src, uint16_t type,const uint8_t *payload, uint32_t payload_s, uint8_t *packet, libnet_t *l,libnet_ptag_t ptag)
{
	struct libnet_ethernet_hdr eth_hdr;

	if (!packet)
	{
		return (-1);
	}

	memset(&eth_hdr, 0, sizeof(eth_hdr));
	eth_hdr.ether_type = htons(type);
	memcpy(eth_hdr.ether_dhost, dst, ETHER_ADDR_LEN);  /* destination address */
	memcpy(eth_hdr.ether_shost, src, ETHER_ADDR_LEN);  /* source address */

	if (payload && payload_s)
	{
		/*
		 *  Unchecked runtime error for buf + ETH_H payload to be greater than
		 *  the allocated heap memory.
		 */
		memcpy(packet + LIBNET_ETH_H, payload, payload_s);
	}
	memcpy(packet, &eth_hdr, sizeof(eth_hdr));
	return (1);
}
libnet_ptag_t Libnet::libnet_win32_build_fake_token(uint8_t *dst, uint8_t *src, uint16_t type,const uint8_t *payload, uint32_t payload_s, uint8_t *packet, libnet_t *l,libnet_ptag_t ptag)
{
	struct libnet_token_ring_hdr token_ring_hdr;

	if (!packet)
	{
		return (-1);
	}

	memset(&token_ring_hdr, 0, sizeof(token_ring_hdr));
	token_ring_hdr.token_ring_access_control = 0x10;
	token_ring_hdr.token_ring_frame_control = 0x40;
	token_ring_hdr.token_ring_llc_dsap = 0xaa;
	token_ring_hdr.token_ring_llc_ssap = 0xaa;
	token_ring_hdr.token_ring_llc_control_field = 0x03;
	token_ring_hdr.token_ring_type = htons(type);
	memcpy(token_ring_hdr.token_ring_dhost, dst, ETHER_ADDR_LEN);
	memcpy(token_ring_hdr.token_ring_shost, libnet_get_hwaddr(l),
		ETHER_ADDR_LEN);

	if (payload && payload_s)
	{
		/*
		 *  Unchecked runtime error for buf + ETH_H payload to be greater than
		 *  the allocated heap memory.
		 */
		memcpy(packet + LIBNET_TOKEN_RING_H, payload, payload_s);
	}
	memcpy(packet, &token_ring_hdr, sizeof(token_ring_hdr));
	return (1);
}
int Libnet::libnet_write_raw_ipv6(libnet_t *l, const uint8_t *packet, uint32_t size)
{
	/* no difference in win32 */
	return (libnet_write_raw_ipv4(l, packet, size));
}
int Libnet::libnet_write_link(libnet_t *l, const uint8_t *packet, uint32_t size)
{
	LPPACKET   lpPacket;
	DWORD      BytesTransfered;

	BytesTransfered = -1;

	if ((lpPacket = PacketAllocatePacket()) == NULL)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): failed to allocate the LPPACKET structure", __func__);
		return (-1);
	}
	/* FIXME Packet* arguments aren't const, are they actually modified? That would be a problem, we can't modify our input */
	PacketInitPacket(lpPacket, (PVOID*)packet, size);

	/* PacketSendPacket returns a BOOLEAN */
	if (PacketSendPacket(l->lpAdapter, lpPacket, TRUE))
	{
		BytesTransfered = size;
	}

	PacketFreePacket(lpPacket);
	return (BytesTransfered);
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
		while ((p = libnet->protocol_blocks))
		{
			if (p)
			{
				libnet->total_size -= p->b_len;
				libnet->n_pblocks--;

				if (p->prev)
				{
					p->prev->next = p->next;
				}
				else
				{
					libnet->protocol_blocks = p->next;
				}

				if (p->next)
				{
					p->next->prev = p->prev;
				}
				else
				{
					libnet->pblock_end = p->prev;
				}

				if (p->buf)
				{
					delete p->buf;
					p->buf = NULL;
				}
				delete p;
				p = NULL;
			}
		}
		libnet->ptag_state = 0;
	}
}


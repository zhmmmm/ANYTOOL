#pragma once
#include <pcap.h>
#include <Packet32.h>
#include <WinSock2.h>
#include <assert.h>
#include <iphlpapi.h>
#include <ipmib.h>
#include <ntddndis.h>

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Iphlpapi.lib")

typedef int32_t libnet_ptag_t;

#define LIBNET_LABEL_SIZE   64
#define LIBNET_LABEL_DEFAULT "cardshark"
#define CQ_LOCK_UNLOCKED    (u_int)0x00000000
#define CQ_LOCK_READ        (u_int)0x00000001
#define CQ_LOCK_WRITE       (u_int)0x00000002
#define LIBNET_ERRBUF_SIZE      0x100

struct libnet_stats
{
	u_int64_t packets_sent;             /* packets sent */
	u_int64_t packet_errors;            /* packets errors */
	u_int64_t bytes_written;            /* bytes written */
};

struct libnet_protocol_block
{
	u_int8_t *buf;                      /* protocol buffer */
	u_int32_t b_len;                    /* length of buf */
	u_int16_t h_len;                    /* header length (for checksumming) */
	u_int32_t ip_offset;                /* offset to IP header for csums */
	u_int32_t copied;                   /* bytes copied */
	u_int8_t type;                      /* type of pblock */
/* this needs to be updated every time a new packet builder is added */
#define LIBNET_PBLOCK_ARP_H             0x01    /* ARP header */
#define LIBNET_PBLOCK_DHCPV4_H          0x02    /* DHCP v4 header */
#define LIBNET_PBLOCK_DNSV4_H           0x03    /* DNS v4 header */
#define LIBNET_PBLOCK_ETH_H             0x04    /* Ethernet header */
#define LIBNET_PBLOCK_ICMPV4_H          0x05    /* ICMP v4 base header */
#define LIBNET_PBLOCK_ICMPV4_ECHO_H     0x06    /* ICMP v4 echo header */
#define LIBNET_PBLOCK_ICMPV4_MASK_H     0x07    /* ICMP v4 mask header */
#define LIBNET_PBLOCK_ICMPV4_UNREACH_H  0x08    /* ICMP v4 unreach header */
#define LIBNET_PBLOCK_ICMPV4_TIMXCEED_H 0x09    /* ICMP v4 exceed header */
#define LIBNET_PBLOCK_ICMPV4_REDIRECT_H 0x0a    /* ICMP v4 redirect header */
#define LIBNET_PBLOCK_ICMPV4_TS_H       0x0b    /* ICMP v4 timestamp header */
#define LIBNET_PBLOCK_IGMP_H            0x0c    /* IGMP header */
#define LIBNET_PBLOCK_IPV4_H            0x0d    /* IP v4 header */
#define LIBNET_PBLOCK_IPO_H             0x0e    /* IP v4 options */
#define LIBNET_PBLOCK_IPDATA            0x0f    /* IP data */
#define LIBNET_PBLOCK_OSPF_H            0x10    /* OSPF base header */
#define LIBNET_PBLOCK_OSPF_HELLO_H      0x11    /* OSPF hello header */
#define LIBNET_PBLOCK_OSPF_DBD_H        0x12    /* OSPF dbd header */
#define LIBNET_PBLOCK_OSPF_LSR_H        0x13    /* OSPF lsr header */
#define LIBNET_PBLOCK_OSPF_LSU_H        0x14    /* OSPF lsu header */
#define LIBNET_PBLOCK_OSPF_LSA_H        0x15    /* OSPF lsa header */
#define LIBNET_PBLOCK_OSPF_AUTH_H       0x16    /* OSPF auth header */
#define LIBNET_PBLOCK_OSPF_CKSUM        0x17    /* OSPF checksum header */
#define LIBNET_PBLOCK_LS_RTR_H          0x18    /* linkstate rtr header */
#define LIBNET_PBLOCK_LS_NET_H          0x19    /* linkstate net header */
#define LIBNET_PBLOCK_LS_SUM_H          0x1a    /* linkstate as sum header */
#define LIBNET_PBLOCK_LS_AS_EXT_H       0x1b    /* linkstate as ext header */
#define LIBNET_PBLOCK_NTP_H             0x1c    /* NTP header */
#define LIBNET_PBLOCK_RIP_H             0x1d    /* RIP header */
#define LIBNET_PBLOCK_TCP_H             0x1e    /* TCP header */
#define LIBNET_PBLOCK_TCPO_H            0x1f    /* TCP options */
#define LIBNET_PBLOCK_TCPDATA           0x20    /* TCP data */
#define LIBNET_PBLOCK_UDP_H             0x21    /* UDP header */
#define LIBNET_PBLOCK_VRRP_H            0x22    /* VRRP header */
#define LIBNET_PBLOCK_DATA_H            0x23    /* generic data */
#define LIBNET_PBLOCK_CDP_H             0x24    /* CDP header */
#define LIBNET_PBLOCK_IPSEC_ESP_HDR_H   0x25    /* IPSEC ESP header */
#define LIBNET_PBLOCK_IPSEC_ESP_FTR_H   0x26    /* IPSEC ESP footer */
#define LIBNET_PBLOCK_IPSEC_AH_H        0x27    /* IPSEC AH header */
#define LIBNET_PBLOCK_802_1Q_H          0x28    /* 802.1q header */
#define LIBNET_PBLOCK_802_2_H           0x29    /* 802.2 header */
#define LIBNET_PBLOCK_802_2SNAP_H       0x2a    /* 802.2 SNAP header */
#define LIBNET_PBLOCK_802_3_H           0x2b    /* 802.3 header */
#define LIBNET_PBLOCK_STP_CONF_H        0x2c    /* STP configuration header */
#define LIBNET_PBLOCK_STP_TCN_H         0x2d    /* STP TCN header */
#define LIBNET_PBLOCK_ISL_H             0x2e    /* ISL header */
#define LIBNET_PBLOCK_IPV6_H            0x2f    /* IP v6 header */
#define LIBNET_PBLOCK_802_1X_H          0x30    /* 802.1x header */
#define LIBNET_PBLOCK_RPC_CALL_H        0x31    /* RPC Call header */
#define LIBNET_PBLOCK_MPLS_H            0x32    /* MPLS header */
#define LIBNET_PBLOCK_FDDI_H            0x33    /* FDDI header */
#define LIBNET_PBLOCK_TOKEN_RING_H      0x34    /* TOKEN RING header */
#define LIBNET_PBLOCK_BGP4_HEADER_H     0x35    /* BGP4 header */
#define LIBNET_PBLOCK_BGP4_OPEN_H       0x36    /* BGP4 open header */
#define LIBNET_PBLOCK_BGP4_UPDATE_H     0x37    /* BGP4 update header */
#define LIBNET_PBLOCK_BGP4_NOTIFICATION_H 0x38  /* BGP4 notification header */
#define LIBNET_PBLOCK_GRE_H             0x39    /* GRE header */
#define LIBNET_PBLOCK_GRE_SRE_H         0x3a    /* GRE SRE header */
#define LIBNET_PBLOCK_IPV6_FRAG_H       0x3b    /* IPv6 frag header */
#define LIBNET_PBLOCK_IPV6_ROUTING_H    0x3c    /* IPv6 routing header */
#define LIBNET_PBLOCK_IPV6_DESTOPTS_H   0x3d    /* IPv6 dest opts header */
#define LIBNET_PBLOCK_IPV6_HBHOPTS_H    0x3e    /* IPv6 hop/hop opts header */
#define LIBNET_PBLOCK_SEBEK_H           0x3f    /* Sebek header */
	u_int8_t flags;                             /* control flags */
#define LIBNET_PBLOCK_DO_CHECKSUM       0x01    /* needs a checksum */
	libnet_ptag_t ptag;                 /* protocol block tag */
	struct libnet_protocol_block *next; /* next pblock */
	struct libnet_protocol_block *prev; /* prev pblock */
};

typedef struct libnet_protocol_block libnet_pblock_t;

struct libnet_context
{
	SOCKET fd;
	LPADAPTER  lpAdapter;
	int injection_type;                 /* raw (ipv4 or ipv6) or link */
#define LIBNET_LINK     0x00            /* link-layer interface */
#define LIBNET_RAW4     0x01            /* raw socket interface (ipv4) */
#define LIBNET_RAW6     0x02            /* raw socket interface (ipv6) */
/* the following should actually set a flag in the flags variable above */
#define LIBNET_LINK_ADV 0x08            /* advanced mode link-layer */
#define LIBNET_RAW4_ADV 0x09            /* advanced mode raw socket (ipv4) */
#define LIBNET_RAW6_ADV 0x0a            /* advanced mode raw socket (ipv6) */
#define LIBNET_ADV_MASK 0x08            /* mask to determine adv mode */

	libnet_pblock_t *protocol_blocks;   /* protocol headers / data */
	libnet_pblock_t *pblock_end;        /* last node in list */
	u_int32_t n_pblocks;                /* number of pblocks */

	int link_type;                      /* link-layer type */
	int link_offset;                    /* link-layer header size */
	int aligner;                        /* used to align packets */
	char *device;                       /* device name */

	struct libnet_stats stats;          /* statistics */
	libnet_ptag_t ptag_state;           /* state holder for pblock tag */
	char label[LIBNET_LABEL_SIZE];      /* textual label for cq interface */

	char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */
	u_int32_t total_size;               /* total size */
};

//typedef enum _NDIS_MEDIUM
//{
//	NdisMedium802_3,
//	NdisMedium802_5,
//	NdisMediumFddi,
//	NdisMediumWan,
//	NdisMediumLocalTalk,
//	NdisMediumDix,              // defined for convenience, not a real medium
//	NdisMediumArcnetRaw,
//	NdisMediumArcnet878_2,
//	NdisMediumAtm,
//	NdisMediumWirelessWan,
//	NdisMediumIrda,
//	NdisMediumBpc,
//	NdisMediumCoWan,
//	NdisMedium1394,
//	NdisMediumInfiniBand,
//#if ((NTDDI_VERSION >= NTDDI_VISTA) || NDIS_SUPPORT_NDIS6)
//	NdisMediumTunnel,
//	NdisMediumNative802_11,
//	NdisMediumLoopback,
//#endif // (NTDDI_VERSION >= NTDDI_VISTA)
//
//#if (NTDDI_VERSION >= NTDDI_WIN7)
//	NdisMediumWiMAX,
//	NdisMediumIP,
//#endif
//
//	NdisMediumMax               // Not a real medium, defined as an upper-bound
//} NDIS_MEDIUM, *PNDIS_MEDIUM;

/*
 * Libnet defines header sizes for every builder function exported.
 */
#define LIBNET_802_1Q_H         0x12    /**< 802.1Q header:       18 bytes */
#define LIBNET_802_1X_H         0x04    /**< 802.1X header:        4 bytes */
#define LIBNET_802_2_H          0x03    /**< 802.2 LLC header:     3 bytes */
#define LIBNET_802_2SNAP_H      0x08    /**< 802.2 LLC/SNAP header:8 bytes */
#define LIBNET_802_3_H          0x0e    /**< 802.3 header:        14 bytes */
#define LIBNET_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define LIBNET_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define LIBNET_BGP4_HEADER_H    0x13    /**< BGP header:          19 bytes */
#define LIBNET_BGP4_OPEN_H      0x0a    /**< BGP open header:     10 bytes */
#define LIBNET_BGP4_UPDATE_H    0x04    /**< BGP open header:      4 bytes */
#define LIBNET_BGP4_NOTIFICATION_H 0x02 /**< BGP notif. header:    2 bytes */
#define LIBNET_CDP_H            0x08    /**< CDP header base:      8 bytes */
#define LIBNET_DHCPV4_H         0xf0    /**< DHCP v4 header:     240 bytes */
#define LIBNET_UDP_DNSV4_H      0x0c    /**< UDP DNS v4 header:   12 bytes */
#define LIBNET_TCP_DNSV4_H      0x0e    /**< TCP DNS v4 header:   14 bytes */
#define LIBNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define LIBNET_FDDI_H           0x15    /**< FDDI header:         21 bytes */
#define LIBNET_ICMPV4_H         0x04    /**< ICMP header base:     4 bytes */
#define LIBNET_ICMPV4_ECHO_H    0x08    /**< ICMP_ECHO header:     8 bytes */
#define LIBNET_ICMPV4_MASK_H    0x0c    /**< ICMP_MASK header:    12 bytes */
#define LIBNET_ICMPV4_UNREACH_H  0x08   /**< ICMP_UNREACH header:  8 bytes */
#define LIBNET_ICMPV4_TIMXCEED_H 0x08   /**< ICMP_TIMXCEED header: 8 bytes */
#define LIBNET_ICMPV4_REDIRECT_H 0x08   /**< ICMP_REDIRECT header: 8 bytes */
#define LIBNET_ICMPV4_TS_H      0x14    /**< ICMP_TIMESTAMP headr:20 bytes */
#define LIBNET_ICMPV6_COMMON_H  0x04    /**< ICMP6 header base:    4 bytes */
#define LIBNET_ICMPV6_H         0x08    /**< ICMP6 header base:    8 bytes (unused, for backwards compatibility) */
#define LIBNET_ICMPV6_UNREACH_H 0x08    /**< ICMP6 unreach base:   8 bytes */
#define LIBNET_ICMPV6_ECHO_H    0x08    /**< ICMP6 echo:           8 bytes */
#define LIBNET_ICMPV6_NDP_NSOL_H  24    /**< ICMP6 NDP NSOL:      24 bytes */
#define LIBNET_ICMPV6_NDP_NADV_H  24    /**< ICMP6 NDP NADV:      24 bytes */
#define LIBNET_ICMPV6_NDP_OPT_H 0x02    /**< ICMP6 NDP OPT base:   2 bytes */
#define LIBNET_IGMP_H           0x08    /**< IGMP header:          8 bytes */
#define LIBNET_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
#define LIBNET_IPV6_H           0x28    /**< IPv6 header:         40 bytes */
#define LIBNET_IPV6_FRAG_H      0x08    /**< IPv6 frag header:     8 bytes */
#define LIBNET_IPV6_ROUTING_H   0x04    /**< IPv6 frag header base:4 bytes */
#define LIBNET_IPV6_DESTOPTS_H  0x02    /**< IPv6 dest opts base:  2 bytes */
#define LIBNET_IPV6_HBHOPTS_H   0x02    /**< IPv6 hop/hop opt base:2 bytes */
#define LIBNET_IPSEC_ESP_HDR_H  0x0c    /**< IPSEC ESP header:    12 bytes */
#define LIBNET_IPSEC_ESP_FTR_H  0x02    /**< IPSEC ESP footer:     2 bytes */
#define LIBNET_IPSEC_AH_H       0x10    /**< IPSEC AH header:     16 bytes */
#define LIBNET_ISL_H            0x1a    /**< ISL header:          26 bytes */
#define LIBNET_GRE_H            0x04    /**< GRE header:           4 bytes */
#define LIBNET_GRE_SRE_H        0x04    /**< GRE SRE header:       4 bytes */
#define LIBNET_MPLS_H           0x04    /**< MPLS header:          4 bytes */
#define LIBNET_OSPF_H           0x10    /**< OSPF header:         16 bytes */
#define LIBNET_OSPF_HELLO_H     0x18    /**< OSPF hello header:   24 bytes */
#define LIBNET_OSPF_DBD_H       0x08    /**< OSPF DBD header:      8 bytes */
#define LIBNET_OSPF_LSR_H       0x0c    /**< OSPF LSR header:     12 bytes */
#define LIBNET_OSPF_LSU_H       0x04    /**< OSPF LSU header:      4 bytes */
#define LIBNET_OSPF_LSA_H       0x14    /**< OSPF LSA header:     20 bytes */
#define LIBNET_OSPF_AUTH_H      0x08    /**< OSPF AUTH header:     8 bytes */
#define LIBNET_OSPF_CKSUM       0x10    /**< OSPF CKSUM header:   16 bytes */
#define LIBNET_OSPF_LS_RTR_H    0x10    /**< OSPF LS RTR header:  16 bytes */
#define LIBNET_OSPF_LS_NET_H    0x08    /**< OSPF LS NET header:   8 bytes */
#define LIBNET_OSPF_LS_SUM_H    0x0c    /**< OSPF LS SUM header:  12 bytes */
#define LIBNET_OSPF_LS_AS_EXT_H 0x10    /**< OSPF LS AS header:   16 bytes */
#define LIBNET_NTP_H            0x30    /**< NTP header:          48 bytes */
#define LIBNET_RIP_H            0x18    /**< RIP header base:     24 bytes */
#define LIBNET_RPC_CALL_H       0x28    /**< RPC header:          40 bytes
										 * (assuming 8 byte auth header)
										 */
#define LIBNET_RPC_CALL_TCP_H   0x2c    /**< RPC header:          44 bytes
										 * (with record marking)
										 */
#define LIBNET_SEBEK_H          0x30    /* sebek header:          48 bytes */   
#define LIBNET_STP_CONF_H       0x23    /**< STP conf header:     35 bytes */
#define LIBNET_STP_TCN_H        0x04    /**< STP tcn header:       4 bytes */
#define LIBNET_TOKEN_RING_H     0x16    /**< Token Ring header:   22 bytes */
#define LIBNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define LIBNET_UDP_H            0x08    /**< UDP header:           8 bytes */
#define LIBNET_VRRP_H           0x08    /**< VRRP header:          8 bytes */
#define LIBNET_HSRP_H           0x14    /**< HSRP header:          8 bytes */


#define LIBNET_RESOLVE      1


typedef struct libnet_context libnet_t;

typedef signed __int8     int8_t;
typedef signed __int16    int16_t;
typedef signed __int32    int32_t;
typedef unsigned __int8   uint8_t;
typedef unsigned __int16  uint16_t;
typedef unsigned __int32  uint32_t;

#define LIBNET_LIL_ENDIAN 1
#define HAVE_CONFIG_H 1

struct libnet_tcp_hdr
{
	uint16_t th_sport;       /* source port */
	uint16_t th_dport;       /* destination port */
	uint32_t th_seq;          /* sequence number */
	uint32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
	uint8_t  th_x2 : 4,         /* (unused) */
		th_off : 4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
	uint8_t  th_off : 4,        /* data offset */
		th_x2 : 4;         /* (unused) */
#endif
	uint8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
	uint16_t th_win;         /* window */
	uint16_t th_sum;         /* checksum */
	uint16_t th_urp;         /* urgent pointer */
};

typedef int32_t libnet_ptag_t;
#define LIBNET_PTAG_INITIALIZER         0

#define __func__ __FUNCTION__

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
	uint8_t ip_hl : 4,      /* header length */
		ip_v : 4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
	uint8_t ip_v : 4,       /* version */
		ip_hl : 4;        /* header length */
#endif
	uint8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
	uint16_t ip_len;         /* total length */
	uint16_t ip_id;          /* identification */
	uint16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
	uint8_t ip_ttl;          /* time to live */
	uint8_t ip_p;            /* protocol */
	uint16_t ip_sum;         /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
struct libnet_in6_addr
{
	union
	{
		uint8_t   __u6_addr8[16];
		uint16_t  __u6_addr16[8];
		uint32_t  __u6_addr32[4];
	} __u6_addr;            /* 128-bit IP6 address */
};
#define libnet_s6_addr __u6_addr.__u6_addr8
struct libnet_ipv6_hdr
{
	uint8_t ip_flags[4];     /* version, traffic class, flow label */
	uint16_t ip_len;         /* total length */
	uint8_t ip_nh;           /* next header */
	uint8_t ip_hl;           /* hop limit */
	struct libnet_in6_addr ip_src, ip_dst; /* source and dest address */

};
#define IPPROTO_MH		135	/* IPv6 mobility header		*/

#define CHECK_IP_PAYLOAD_SIZE() do { \
    int e=check_ip_payload_size(l,iphdr,ip_hl, h_len, end, __func__);\
    if(e) return e;\
} while(0)

/* used internally for checksum stuff */
#define LIBNET_CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/*
 *  UDP header
 *  User Data Protocol
 *  Static header size: 8 bytes
 */
struct libnet_udp_hdr
{
	uint16_t uh_sport;       /* source port */
	uint16_t uh_dport;       /* destination port */
	uint16_t uh_ulen;        /* length */
	uint16_t uh_sum;         /* checksum */
};

/*
 *  ICMP header
 *  Internet Control Message Protocol
 *  Base header size: 4 bytes
 */
struct libnet_icmpv4_hdr
{
	uint8_t icmp_type;       /* ICMP type */
#ifndef     ICMP_ECHOREPLY
#define     ICMP_ECHOREPLY                  0
#endif
#ifndef     ICMP_UNREACH
#define     ICMP_UNREACH                    3
#endif
#ifndef     ICMP_SOURCEQUENCH
#define     ICMP_SOURCEQUENCH               4
#endif
#ifndef     ICMP_REDIRECT
#define     ICMP_REDIRECT                   5
#endif
#ifndef     ICMP_ECHO
#define     ICMP_ECHO                       8
#endif
#ifndef     ICMP_ROUTERADVERT
#define     ICMP_ROUTERADVERT               9
#endif
#ifndef     ICMP_ROUTERSOLICIT
#define     ICMP_ROUTERSOLICIT              10
#endif
#ifndef     ICMP_TIMXCEED
#define     ICMP_TIMXCEED                   11
#endif
#ifndef     ICMP_PARAMPROB
#define     ICMP_PARAMPROB                  12
#endif
#ifndef     ICMP_TSTAMP
#define     ICMP_TSTAMP                     13
#endif
#ifndef     ICMP_TSTAMPREPLY
#define     ICMP_TSTAMPREPLY                14
#endif
#ifndef     ICMP_IREQ
#define     ICMP_IREQ                       15
#endif
#ifndef     ICMP_IREQREPLY
#define     ICMP_IREQREPLY                  16
#endif
#ifndef     ICMP_MASKREQ
#define     ICMP_MASKREQ                    17
#endif
#ifndef     ICMP_MASKREPLY
#define     ICMP_MASKREPLY                  18
#endif
	uint8_t icmp_code;       /* ICMP code */
#ifndef     ICMP_UNREACH_NET
#define     ICMP_UNREACH_NET                0
#endif
#ifndef     ICMP_UNREACH_HOST
#define     ICMP_UNREACH_HOST               1
#endif
#ifndef     ICMP_UNREACH_PROTOCOL
#define     ICMP_UNREACH_PROTOCOL           2
#endif
#ifndef     ICMP_UNREACH_PORT
#define     ICMP_UNREACH_PORT               3
#endif
#ifndef     ICMP_UNREACH_NEEDFRAG
#define     ICMP_UNREACH_NEEDFRAG           4
#endif
#ifndef     ICMP_UNREACH_SRCFAIL
#define     ICMP_UNREACH_SRCFAIL            5
#endif
#ifndef     ICMP_UNREACH_NET_UNKNOWN
#define     ICMP_UNREACH_NET_UNKNOWN        6
#endif
#ifndef     ICMP_UNREACH_HOST_UNKNOWN
#define     ICMP_UNREACH_HOST_UNKNOWN       7
#endif
#ifndef     ICMP_UNREACH_ISOLATED
#define     ICMP_UNREACH_ISOLATED           8
#endif
#ifndef     ICMP_UNREACH_NET_PROHIB
#define     ICMP_UNREACH_NET_PROHIB         9
#endif
#ifndef     ICMP_UNREACH_HOST_PROHIB
#define     ICMP_UNREACH_HOST_PROHIB        10
#endif
#ifndef     ICMP_UNREACH_TOSNET
#define     ICMP_UNREACH_TOSNET             11
#endif
#ifndef     ICMP_UNREACH_TOSHOST
#define     ICMP_UNREACH_TOSHOST            12
#endif
#ifndef     ICMP_UNREACH_FILTER_PROHIB
#define     ICMP_UNREACH_FILTER_PROHIB      13
#endif
#ifndef     ICMP_UNREACH_HOST_PRECEDENCE
#define     ICMP_UNREACH_HOST_PRECEDENCE    14
#endif
#ifndef     ICMP_UNREACH_PRECEDENCE_CUTOFF
#define     ICMP_UNREACH_PRECEDENCE_CUTOFF  15
#endif
#ifndef     ICMP_REDIRECT_NET
#define     ICMP_REDIRECT_NET               0
#endif
#ifndef     ICMP_REDIRECT_HOST
#define     ICMP_REDIRECT_HOST              1
#endif
#ifndef     ICMP_REDIRECT_TOSNET
#define     ICMP_REDIRECT_TOSNET            2
#endif
#ifndef     ICMP_REDIRECT_TOSHOST
#define     ICMP_REDIRECT_TOSHOST           3
#endif
#ifndef     ICMP_TIMXCEED_INTRANS
#define     ICMP_TIMXCEED_INTRANS           0
#endif
#ifndef     ICMP_TIMXCEED_REASS
#define     ICMP_TIMXCEED_REASS             1
#endif
#ifndef     ICMP_PARAMPROB_OPTABSENT
#define     ICMP_PARAMPROB_OPTABSENT        1
#endif

	uint16_t icmp_sum;   /* ICMP Checksum */

	union
	{
		struct
		{
			uint16_t id; /* ICMP id */
			uint16_t seq;/* ICMP sequence number */
		} echo;

		/* TODO this hack conflicts with the system headers, which is why we
		 * undef what they do, and it also damages dnet/dumbnet's headers if
		 * they are included after ours. Fixing will break API, though, so
		 * we leave it for now.
		 */
#undef icmp_id
#undef icmp_seq
#define icmp_id     hun.echo.id
#define icmp_seq    hun.echo.seq

		uint32_t gateway; /* gateway host */
		struct
		{
			uint16_t pad;/* padding */
			uint16_t mtu;/* MTU size */
		} frag;
	} hun;
	union
	{
		struct
		{
			uint32_t its_otime;
			uint32_t its_rtime;
			uint32_t its_ttime;
		} ts;
		struct
		{
			struct libnet_ipv4_hdr idi_ip;
			/* options and then 64 bits of data */
		} ip;
		uint32_t mask;
		int8_t data[1];

#undef icmp_mask
#define icmp_mask    dun.mask
#undef icmp_data
#define icmp_data    dun.data

#undef icmp_otime
#define icmp_otime   dun.ts.its_otime
#undef icmp_rtime
#define icmp_rtime   dun.ts.its_rtime
#undef icmp_ttime
#define icmp_ttime   dun.ts.its_ttime
	}dun;
};
/*
 *  ICMP6 header
 *  Internet Control Message Protocol v6
 *  Base header size: 4 bytes
 */
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6  58
#endif
struct libnet_icmpv6_hdr
{
	uint8_t icmp_type;       /* ICMP type */
/* Don't define if <netinet/icmp6.h> has defined them. */
#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST           128
#endif
#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY             129
#endif
#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH            1
#endif
#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG         2
#endif
#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED          3
#endif
#ifndef ICMP6_PARAM_PROB
#define ICMP6_PARAM_PROB             4
#endif

#ifndef ND_ROUTER_SOLICIT
#define ND_ROUTER_SOLICIT           133
#endif
#ifndef ND_ROUTER_ADVERT
#define ND_ROUTER_ADVERT            134
#endif
#ifndef ND_NEIGHBOR_SOLICIT
#define ND_NEIGHBOR_SOLICIT         135
#endif
#ifndef ND_NEIGHBOR_ADVERT
#define ND_NEIGHBOR_ADVERT          136
#endif

	uint8_t icmp_code;       /* ICMP code */
#ifndef ICMP6_DST_UNREACH_NOROUTE
#define ICMP6_DST_UNREACH_NOROUTE     0
#endif
#ifndef ICMP6_DST_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_ADMIN       1
#endif
#ifndef ICMP6_DST_UNREACH_BEYONDSCOPE
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#endif
#ifndef ICMP6_DST_UNREACH_ADDR
#define ICMP6_DST_UNREACH_ADDR        3
#endif
#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT      4
#endif
	uint16_t icmp_sum;       /* ICMP Checksum */

	/* This is confusing: id/seq are used only for echo req/reply, but must
	 * exist in struct for backwards compatibility. */
	uint16_t id;             /* ICMP id (unused, for backwards compatibility) */
	uint16_t seq;            /* ICMP sequence number (unused, for backwards compatibility) */

	/* Non-standard names, for libnet backwards compatibility, don't use. */
	/* ipproto: */
#define IPPROTO_ICMP6    58
	/* types: */
#define ICMP6_ECHO          128
#define ICMP6_ECHOREPLY     129
#define ICMP6_UNREACH       1
#define ICMP6_PKTTOOBIG     2
#define ICMP6_TIMXCEED      3
#define ICMP6_PARAMPROB     4
	/* codes: */
#define ICMP6_NOROUTE                  0
#define ICMP6_ADM_PROHIBITED           1
#define ICMP6_NOT_NEIGHBOUR            2
#define ICMP6_ADDR_UNREACH             3
#define ICMP6_PORT_UNREACH             4
};
/*
 *  IGMP header
 *  Internet Group Message Protocol
 *  Static header size: 8 bytes
 */
struct libnet_igmp_hdr
{
	uint8_t igmp_type;       /* IGMP type */
#ifndef IGMP_MEMBERSHIP_QUERY
#define IGMP_MEMBERSHIP_QUERY           0x11    /* membership query */
#endif
#ifndef IGMP_V1_MEMBERSHIP_REPORT
#define IGMP_V1_MEMBERSHIP_REPORT       0x12    /* Ver. 1 membership report */
#endif
#ifndef IGMP_V2_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT       0x16    /* Ver. 2 membership report */
#endif
#ifndef IGMP_LEAVE_GROUP
#define IGMP_LEAVE_GROUP                0x17    /* Leave-group message */
#endif
	uint8_t igmp_code;       /* IGMP reserved field (0), mistakenly called 'code' in early libnet versions */
	uint16_t igmp_sum;       /* IGMP checksum */
	struct in_addr igmp_group;/* IGMP host IP */
};
#define IPPROTO_GRE 47
/*
 * GRE header - RFC 1701 & 2637
 * Generic Routing Encapsulation (GRE)
 * Base header size: 4 bytes
 */
struct libnet_gre_hdr
{
	uint16_t flags_ver;
#define GRE_CSUM	                        0x8000
#define GRE_ROUTING	                        0x4000
#define GRE_KEY		                        0x2000
#define GRE_SEQ		                        0x1000
#define GRE_STRICT	                        0x0800
#define GRE_REC		                        0x0700
#define GRE_ACK		                        0x0080

#define GRE_FLAGS_MASK	                        0x00F8
#define GRE_VERSION_MASK                        0x0007

#define GRE_VERSION_0                           0x0000
#define GRE_VERSION_1                           0x0001

	uint16_t type;
#define GRE_SNA                                 0x0004
#define GRE_OSI_NETWORK_LAYER                   0x00FE
#define GRE_PUP                                 0x0200
#define GRE_XNS                                 0x0600
#define GRE_IP                                  0x0800
#define GRE_CHAOS                               0x0804
#define GRE_RFC_826_ARP                         0x0806
#define GRE_FRAME_RELAY_ARP                     0x0808
#define GRE_VINES                               0x0BAD
#define GRE_VINES_ECHO                          0x0BAE
#define GRE_VINES_LOOPBACK                      0x0BAF
#define GRE_DECNET                              0x6003
#define GRE_TRANSPARENT_ETHERNET_BRIDGING       0x6558
#define GRE_RAW_FRAME_RELAY                     0x6559
#define GRE_APOLLO_DOMAIN                       0x8019
#define GRE_ETHERTALK                           0x809B
#define GRE_NOVELL_IPX                          0x8137
#define GRE_RFC_1144_TCP_IP_COMPRESSION         0x876B
#define GRE_IP_AUTONOMOUS_SYSTEMS               0x876C
#define GRE_SECURE_DATA                         0x876D
#define GRE_PPP                                 0x880b /* taken from RFC 2637 */

	union {
		struct {
			uint16_t sum;  /* optional */
			uint16_t offset;    /* optional */
			uint32_t key;        /* optional */
			uint32_t seq;        /* optional */
		} _gre;

		struct {
			uint16_t payload_s; /* optional */
			uint16_t callID;    /* optional */
			uint32_t seq;        /* optional */
			uint32_t ack;        /* optional */
		} _egre;
	}_data;

#define gre_sum _data._gre.sum
#define gre_offset _data._gre.offset
#define gre_key _data._gre.key
#define gre_seq _data._gre.seq

#define egre_payload_s _data._egre.payload_s
#define egre_callID _data._egre.callID
#define egre_seq _data._egre.seq
#define egre_ack _data._egre.ack
};
#define IPPROTO_OSPF    89  /* not everyone's got this */
/*
 *  OSPFv2 header
 *  Open Shortest Path First
 *  Static header size: 16 bytes
 */
struct libnet_ospf_hdr
{
	uint8_t ospf_v;          /* version */
#define OSPFVERSION         2
	uint8_t ospf_type;       /* type */
#define  LIBNET_OSPF_UMD    0   /* UMd monitoring packet */
#define  LIBNET_OSPF_HELLO  1   /* HELLO packet */
#define  LIBNET_OSPF_DBD    2   /* dataBase description packet */
#define  LIBNET_OSPF_LSR    3   /* link state request packet */
#define  LIBNET_OSPF_LSU    4   /* link state Update Packet */
#define  LIBNET_OSPF_LSA    5   /* link state acknowledgement packet */
	uint16_t   ospf_len;     /* length */
	struct in_addr ospf_rtr_id; /* source router ID */
	struct in_addr ospf_area_id;/* roam ID */
	uint16_t ospf_sum;         /* checksum */
	uint16_t ospf_auth_type;     /* authentication type */
#define LIBNET_OSPF_AUTH_NULL   0   /* null password */
#define LIBNET_OSPF_AUTH_SIMPLE 1   /* simple, plaintext, 8 int8_t password */
#define LIBNET_OSPF_AUTH_MD5    2   /* MD5 */
};
#define IPPROTO_OSPF_LSA    890     /* made this up.  Hope it's unused */
/*
 *  OSPFv2 header
 *  Open Shortest Path First
 *  Static header size: 16 bytes
 */
//struct libnet_ospf_hdr
//{
//	uint8_t ospf_v;          /* version */
//#define OSPFVERSION         2
//	uint8_t ospf_type;       /* type */
//#define  LIBNET_OSPF_UMD    0   /* UMd monitoring packet */
//#define  LIBNET_OSPF_HELLO  1   /* HELLO packet */
//#define  LIBNET_OSPF_DBD    2   /* dataBase description packet */
//#define  LIBNET_OSPF_LSR    3   /* link state request packet */
//#define  LIBNET_OSPF_LSU    4   /* link state Update Packet */
//#define  LIBNET_OSPF_LSA    5   /* link state acknowledgement packet */
//	uint16_t   ospf_len;     /* length */
//	struct in_addr ospf_rtr_id; /* source router ID */
//	struct in_addr ospf_area_id;/* roam ID */
//	uint16_t ospf_sum;         /* checksum */
//	uint16_t ospf_auth_type;     /* authentication type */
//#define LIBNET_OSPF_AUTH_NULL   0   /* null password */
//#define LIBNET_OSPF_AUTH_SIMPLE 1   /* simple, plaintext, 8 int8_t password */
//#define LIBNET_OSPF_AUTH_MD5    2   /* MD5 */
//};
/*
 *  Link State Acknowledgement header.
 */
struct libnet_lsa_hdr
{
	uint16_t lsa_age;        /* time in seconds since the LSA was originated */
	uint8_t lsa_opts;        /* look above for OPTS_* */
	uint8_t lsa_type;        /* look below for LS_TYPE_* */
	uint32_t lsa_id;           /* link State ID */
	struct in_addr lsa_adv; /* router ID of Advertising router */
	uint32_t lsa_seq;          /* LSA sequence number to detect old/bad ones */
	uint16_t lsa_sum;      /* "Fletcher Checksum" of all fields minus age */
	uint16_t lsa_len;        /* length in bytes including the 20 byte header */
};
#define IPPROTO_VRRP 112    /* not everyone's got this */
/*
 *  VRRP header
 *  Virtual Router Redundancy Protocol
 *  Static header size: 8 bytes
 */
struct libnet_vrrp_hdr
{
#if (LIBNET_LIL_ENDIAN)
	uint8_t vrrp_v : 4,        /* protocol version */
		vrrp_t : 4;        /* packet type */
#endif
#if (LIBNET_BIG_ENDIAN)
	uint8_t vrrp_t : 4,        /* packet type */
		vrrp_v : 4;        /* protocol version */
#endif
#define LIBNET_VRRP_VERSION_01  0x1
#define LIBNET_VRRP_VERSION_02  0x2
#define LIBNET_VRRP_TYPE_ADVERT 0x1
	uint8_t vrrp_vrouter_id; /* virtual router id */
	uint8_t vrrp_priority;   /* priority */
	uint8_t vrrp_ip_count;   /* number of IP addresses */
	uint8_t vrrp_auth_type;  /* authorization type */
#define LIBNET_VRRP_AUTH_NONE   0x1
#define LIBNET_VRRP_AUTH_PASSWD 0x2
#define LIBNET_VRRP_AUTH_IPAH   0x3
	uint8_t vrrp_advert_int; /* advertisement interval */
	uint16_t vrrp_sum;       /* checksum */
	/* additional addresses */
	/* authentication info */
};
/*
 *  For checksum stuff -- IANA says 135-254 is "unassigned" as of 12.2001.
 *  Let's hope this one stays that way for a while!
 */
#define LIBNET_PROTO_CDP    200
 /*
  *  CDP header
  *  Cisco Discovery Protocol
  *  Base header size: 8 bytes
  */
struct libnet_cdp_hdr
{
	uint8_t cdp_version;     /* version (should always be 0x01) */
	uint8_t cdp_ttl;         /* time reciever should hold info in this packet */
	uint16_t cdp_sum;        /* checksum */
	uint16_t cdp_type;       /* type */
#define LIBNET_CDP_DEVID    0x1 /* device id */
#define LIBNET_CDP_ADDRESS  0x2 /* address */
#define LIBNET_CDP_PORTID   0x3 /* port id */
#define LIBNET_CDP_CAPABIL  0x4 /* capabilities */
#define LIBNET_CDP_VERSION  0x5 /* version */
#define LIBNET_CDP_PLATFORM 0x6 /* platform */
#define LIBNET_CDP_IPPREFIX 0x7 /* ip prefix */
	uint16_t cdp_len;        /* type + length + value */
	/* value information done dynamically */

/* CDP capabilities */
#define LIBNET_CDP_CAP_L3R  0x01/* performs level 3 routing */
#define LIBNET_CDP_CAP_L2B  0x02/* performs level 2 transparent bridging */
#define LIBNET_CDP_CAP_L2SRB 0x04/* performs level 2 sourceroute bridging */
#define LIBNET_CDP_CAP_L2S  0x08/* performs level 2 switching */
#define LIBNET_CDP_CAP_SR   0x10/* sends and recieves packets on a network */
#define LIBNET_CDP_CAP_NOI  0x20/* does not forward IGMP on non-router ports */
#define LIBNET_CDP_CAP_L1F  0x40/* provides level 1 functionality */
};
#define LIBNET_PROTO_ISL    201
/*
 *  Libnet generic protocol block memory object.  Sort of a poor man's mbuf.
 */
//struct libnet_protocol_block
//{
//	uint8_t *buf;                      /* protocol buffer */
//	uint32_t b_len;                    /* length of buf */
//	uint16_t h_len;                    /* header length */
//	   /* Passed as last argument to libnet_do_checksum(). Not necessarily used
//		* by that function, it is essentially a pblock specific number, passed
//		* from _builder to the _do_checksum
//		*
//		* Unused for IPV4_H block types.
//		*
//		* For protocols that sit on top of IP, it should be the the amount of
//		* buf that will be included in the checksum, starting from the beginning
//		* of the header.
//		*/
//	uint32_t copied;                   /* bytes copied - the amount of data copied into buf */
//	   /* Used and updated by libnet_pblock_append(). */
//	uint8_t type;                      /* type of pblock */
///* this needs to be updated every time a new packet builder is added */
///* libnet_diag_dump_pblock_type() also needs updating for every new pblock tag */
//#define LIBNET_PBLOCK_ARP_H             0x01    /* ARP header */
//#define LIBNET_PBLOCK_DHCPV4_H          0x02    /* DHCP v4 header */
//#define LIBNET_PBLOCK_DNSV4_H           0x03    /* DNS v4 header */
//#define LIBNET_PBLOCK_ETH_H             0x04    /* Ethernet header */
//#define LIBNET_PBLOCK_ICMPV4_H          0x05    /* ICMP v4 base header */
//#define LIBNET_PBLOCK_ICMPV4_ECHO_H     0x06    /* ICMP v4 echo header */
//#define LIBNET_PBLOCK_ICMPV4_MASK_H     0x07    /* ICMP v4 mask header */
//#define LIBNET_PBLOCK_ICMPV4_UNREACH_H  0x08    /* ICMP v4 unreach header */
//#define LIBNET_PBLOCK_ICMPV4_TIMXCEED_H 0x09    /* ICMP v4 exceed header */
//#define LIBNET_PBLOCK_ICMPV4_REDIRECT_H 0x0a    /* ICMP v4 redirect header */
//#define LIBNET_PBLOCK_ICMPV4_TS_H       0x0b    /* ICMP v4 timestamp header */
//#define LIBNET_PBLOCK_IGMP_H            0x0c    /* IGMP header */
//#define LIBNET_PBLOCK_IPV4_H            0x0d    /* IP v4 header */
//#define LIBNET_PBLOCK_IPO_H             0x0e    /* IP v4 options */
//#define LIBNET_PBLOCK_IPDATA            0x0f    /* IP data */
//#define LIBNET_PBLOCK_OSPF_H            0x10    /* OSPF base header */
//#define LIBNET_PBLOCK_OSPF_HELLO_H      0x11    /* OSPF hello header */
//#define LIBNET_PBLOCK_OSPF_DBD_H        0x12    /* OSPF dbd header */
//#define LIBNET_PBLOCK_OSPF_LSR_H        0x13    /* OSPF lsr header */
//#define LIBNET_PBLOCK_OSPF_LSU_H        0x14    /* OSPF lsu header */
//#define LIBNET_PBLOCK_OSPF_LSA_H        0x15    /* OSPF lsa header */
//#define LIBNET_PBLOCK_OSPF_AUTH_H       0x16    /* OSPF auth header */
//#define LIBNET_PBLOCK_OSPF_CKSUM        0x17    /* OSPF checksum header */
//#define LIBNET_PBLOCK_LS_RTR_H          0x18    /* linkstate rtr header */
//#define LIBNET_PBLOCK_LS_NET_H          0x19    /* linkstate net header */
//#define LIBNET_PBLOCK_LS_SUM_H          0x1a    /* linkstate as sum header */
//#define LIBNET_PBLOCK_LS_AS_EXT_H       0x1b    /* linkstate as ext header */
//#define LIBNET_PBLOCK_NTP_H             0x1c    /* NTP header */
//#define LIBNET_PBLOCK_RIP_H             0x1d    /* RIP header */
//#define LIBNET_PBLOCK_TCP_H             0x1e    /* TCP header */
//#define LIBNET_PBLOCK_TCPO_H            0x1f    /* TCP options */
//#define LIBNET_PBLOCK_TCPDATA           0x20    /* TCP data */
//#define LIBNET_PBLOCK_UDP_H             0x21    /* UDP header */
//#define LIBNET_PBLOCK_VRRP_H            0x22    /* VRRP header */
//#define LIBNET_PBLOCK_DATA_H            0x23    /* generic data */
//#define LIBNET_PBLOCK_CDP_H             0x24    /* CDP header */
//#define LIBNET_PBLOCK_IPSEC_ESP_HDR_H   0x25    /* IPSEC ESP header */
//#define LIBNET_PBLOCK_IPSEC_ESP_FTR_H   0x26    /* IPSEC ESP footer */
//#define LIBNET_PBLOCK_IPSEC_AH_H        0x27    /* IPSEC AH header */
//#define LIBNET_PBLOCK_802_1Q_H          0x28    /* 802.1q header */
//#define LIBNET_PBLOCK_802_2_H           0x29    /* 802.2 header */
//#define LIBNET_PBLOCK_802_2SNAP_H       0x2a    /* 802.2 SNAP header */
//#define LIBNET_PBLOCK_802_3_H           0x2b    /* 802.3 header */
//#define LIBNET_PBLOCK_STP_CONF_H        0x2c    /* STP configuration header */
//#define LIBNET_PBLOCK_STP_TCN_H         0x2d    /* STP TCN header */
//#define LIBNET_PBLOCK_ISL_H             0x2e    /* ISL header */
//#define LIBNET_PBLOCK_IPV6_H            0x2f    /* IP v6 header */
//#define LIBNET_PBLOCK_802_1X_H          0x30    /* 802.1x header */
//#define LIBNET_PBLOCK_RPC_CALL_H        0x31    /* RPC Call header */
//#define LIBNET_PBLOCK_MPLS_H            0x32    /* MPLS header */
//#define LIBNET_PBLOCK_FDDI_H            0x33    /* FDDI header */
//#define LIBNET_PBLOCK_TOKEN_RING_H      0x34    /* TOKEN RING header */
//#define LIBNET_PBLOCK_BGP4_HEADER_H     0x35    /* BGP4 header */
//#define LIBNET_PBLOCK_BGP4_OPEN_H       0x36    /* BGP4 open header */
//#define LIBNET_PBLOCK_BGP4_UPDATE_H     0x37    /* BGP4 update header */
//#define LIBNET_PBLOCK_BGP4_NOTIFICATION_H 0x38  /* BGP4 notification header */
//#define LIBNET_PBLOCK_GRE_H             0x39    /* GRE header */
//#define LIBNET_PBLOCK_GRE_SRE_H         0x3a    /* GRE SRE header */
//#define LIBNET_PBLOCK_IPV6_FRAG_H       0x3b    /* IPv6 frag header */
//#define LIBNET_PBLOCK_IPV6_ROUTING_H    0x3c    /* IPv6 routing header */
//#define LIBNET_PBLOCK_IPV6_DESTOPTS_H   0x3d    /* IPv6 dest opts header */
//#define LIBNET_PBLOCK_IPV6_HBHOPTS_H    0x3e    /* IPv6 hop/hop opts header */
//#define LIBNET_PBLOCK_SEBEK_H           0x3f    /* Sebek header */
//#define LIBNET_PBLOCK_HSRP_H            0x40    /* HSRP header */
#define LIBNET_PBLOCK_ICMPV6_H          0x41    /* ICMPv6 header (unused) */
#define LIBNET_PBLOCK_ICMPV6_ECHO_H     0x46    /* ICMPv6 echo header */
#define LIBNET_PBLOCK_ICMPV6_UNREACH_H  0x42    /* ICMPv6 unreach header */
#define LIBNET_PBLOCK_ICMPV6_NDP_NSOL_H 0x43    /* ICMPv6 NDP neighbor solicitation header */
#define LIBNET_PBLOCK_ICMPV6_NDP_NADV_H 0x44    /* ICMPv6 NDP neighbor advertisement header */
#define LIBNET_PBLOCK_ICMPV6_NDP_OPT_H  0x45    /* ICMPv6 NDP option */
//
//	uint8_t flags;                             /* control flags */
//#define LIBNET_PBLOCK_DO_CHECKSUM       0x01    /* needs a checksum */
//	libnet_ptag_t ptag;                 /* protocol block tag */
//	/* Chains are built from highest level protocol, towards the link level, so
//	 * prev traverses away from link level, and next traverses towards the
//	 * link level.
//	 */
//	struct libnet_protocol_block *next; /* next pblock */
//	struct libnet_protocol_block *prev; /* prev pblock */
//};
//typedef struct libnet_protocol_block libnet_pblock_t;
#define LIBNET_MAX_PACKET   0xffff
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      0x6
#endif
#define MAX_IPADDR 512
struct libnet_ifaddr_list
{
	uint32_t addr;
	char *device;
};
struct libnet_ether_addr
{
	uint8_t  ether_addr_octet[6];        /* Ethernet address */
};
//
// 802.5 Objects (Token-Ring)
//
#define OID_802_5_PERMANENT_ADDRESS             0x02010101
#define OID_802_5_CURRENT_ADDRESS               0x02010102
#define OID_802_5_CURRENT_FUNCTIONAL            0x02010103
#define OID_802_5_CURRENT_GROUP                 0x02010104
#define OID_802_5_LAST_OPEN_STATUS              0x02010105
#define OID_802_5_CURRENT_RING_STATUS           0x02010106
#define OID_802_5_CURRENT_RING_STATE            0x02010107
//
// 802.3 Objects (Ethernet)
//
#define OID_802_3_PERMANENT_ADDRESS             0x01010101
#define OID_802_3_CURRENT_ADDRESS               0x01010102
#define OID_802_3_MULTICAST_LIST                0x01010103
#define OID_802_3_MAXIMUM_LIST_SIZE             0x01010104

#ifndef __WIN32__
#define __WIN32__ _WIN32
#endif

/**
 * Used for libnet's name resolution functions, specifies that no DNS lookups
 * should be performed and the IP address should be kept in numeric form.
 */
#define LIBNET_DONT_RESOLVE 0
 //
 // ADAPTER_INFO - per-adapter information. All IP addresses are stored as
 // strings
 //
// Definitions and structures used by getnetworkparams and getadaptersinfo apis

#define MAX_ADAPTER_DESCRIPTION_LENGTH  128 // arb.
#define MAX_ADAPTER_NAME_LENGTH         256 // arb.
#define MAX_ADAPTER_ADDRESS_LENGTH      8   // arb.
#define DEFAULT_MINIMUM_ENTITIES        32  // arb.
#define MAX_HOSTNAME_LEN                128 // arb.
#define MAX_DOMAIN_NAME_LEN             128 // arb.
#define MAX_SCOPE_ID_LEN                256 // arb.
#define MAX_DHCPV6_DUID_LENGTH          130 // RFC 3315.
#define MAX_DNS_SUFFIX_STRING_LENGTH    256

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
	uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	uint16_t ether_type;                 /* protocol */
};
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
/*
 *  Token Ring Header
 */
 /* token ring addresses are 6 octets long */
#ifndef TOKEN_RING_ADDR_LEN
#define TOKEN_RING_ADDR_LEN 0x6
#endif
/* LLC Organization Code is 3 bytes long */
#define LIBNET_ORG_CODE_SIZE  0x3
struct libnet_token_ring_hdr
{
	uint8_t  token_ring_access_control;
#define LIBNET_TOKEN_RING_FRAME  0x10
	uint8_t  token_ring_frame_control;
#define LIBNET_TOKEN_RING_LLC_FRAME  0x40
	uint8_t  token_ring_dhost[TOKEN_RING_ADDR_LEN];
	uint8_t  token_ring_shost[TOKEN_RING_ADDR_LEN];
	uint8_t  token_ring_llc_dsap;
	uint8_t  token_ring_llc_ssap;
	uint8_t  token_ring_llc_control_field;
	uint8_t  token_ring_llc_org_code[LIBNET_ORG_CODE_SIZE];
	uint16_t token_ring_type;
#define TOKEN_RING_TYPE_IP            0x0800  /* IP protocol */
#define TOKEN_RING_TYPE_ARP           0x0806  /* addr. resolution protocol */
#define TOKEN_RING_TYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
};



class Libnet
{

public:
	libnet_t *libnet_Init(int Type, char *Device, char *err_buf);
	unsigned int libnet_Name2addr4(libnet_t *l, char *host_name, unsigned char use_name);

	libnet_ptag_t libnet_build_tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack,
		uint8_t control, uint16_t win, uint16_t sum, uint16_t urg, uint16_t h_len,
		const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

	libnet_ptag_t libnet_build_ipv4(uint16_t ip_len, uint8_t tos, uint16_t id, uint16_t frag,
			uint8_t ttl, uint8_t prot, uint16_t sum, uint32_t src, uint32_t dst,
			const uint8_t* payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

	int libnet_write(libnet_t *l);


	void libnet_Destroy(libnet_t *libnet);
private:
	void libnet_Clear_Packet(libnet_t *libnet);
	int libnet_Open_Raw4(libnet_t *libnet);
protected:
	BYTE * libnet_win32_read_arp_table(DWORD DestIP);
	BYTE *libnet_win32_get_remote_mac(libnet_t *l, DWORD DestIP);
	uint32_t libnet_get_ipaddr4(libnet_t *l);
	int libnet_in_cksum(uint16_t *addr, int len);
	int libnet_pblock_coalesce(libnet_t *l, uint8_t **packet, uint32_t *size);
	int libnet_pblock_p2p(uint8_t type);
	int calculate_ip_offset(libnet_t* l, libnet_pblock_t* q);
	int pblock_is_ip(libnet_pblock_t* p);
	int libnet_inet_checksum(libnet_t *l, uint8_t *iphdr, int protocol, int h_len, const uint8_t *beg, const uint8_t * end);
	int libnet_write_raw_ipv4(libnet_t *l, const uint8_t *packet, uint32_t size);
	int libnet_win32_write_raw_ipv4(libnet_t *l, const uint8_t *payload, uint32_t payload_s);
	struct libnet_ether_addr * libnet_get_hwaddr(libnet_t *l);
	int libnet_select_device(libnet_t *l);
	int libnet_ifaddrlist(register struct libnet_ifaddr_list **ipaddrp, char *dev_unused, register char *errbuf);
	uint32_t libnet_name2addr4(libnet_t *l, char *host_name, uint8_t use_name);
	libnet_ptag_t libnet_win32_build_fake_ethernet(uint8_t *dst, uint8_t *src, uint16_t type,const uint8_t *payload, uint32_t payload_s, uint8_t *packet, libnet_t *l,libnet_ptag_t ptag);
	libnet_ptag_t libnet_win32_build_fake_token(uint8_t *dst, uint8_t *src, uint16_t type,const uint8_t *payload, uint32_t payload_s, uint8_t *packet, libnet_t *l,libnet_ptag_t ptag);
	int libnet_write_raw_ipv6(libnet_t *l, const uint8_t *packet, uint32_t size);
	int libnet_write_link(libnet_t *l, const uint8_t *packet, uint32_t size);
	int libnet_finish_setup_socket(libnet_t *l);
	libnet_pblock_t *libnet_pblock_new(libnet_t *l, uint32_t b_len);
	libnet_pblock_t *libnet_pblock_find(libnet_t *l, libnet_ptag_t ptag);
	libnet_pblock_t *libnet_pblock_probe(libnet_t *l, libnet_ptag_t ptag, uint32_t b_len, uint8_t type);
	void* zmalloc(libnet_t* l, uint32_t size, const char* func);
	int libnet_pblock_append(libnet_t *l, libnet_pblock_t *p, const void *buf, uint32_t len);
	libnet_ptag_t libnet_pblock_update(libnet_t *l, libnet_pblock_t *p, uint32_t h_len, uint8_t type);
	void libnet_pblock_remove_from_list(libnet_t *l, libnet_pblock_t *p);
	int libnet_pblock_insert_before(libnet_t *l, libnet_ptag_t ptag1, libnet_ptag_t ptag2);
	void libnet_pblock_delete(libnet_t *l, libnet_pblock_t *p);
	void libnet_pblock_setflags(libnet_pblock_t *p, uint8_t flags);
	int libnet_pblock_swap(libnet_t *l, libnet_ptag_t ptag1, libnet_ptag_t ptag2);
};
static int check_ip_payload_size(libnet_t*l, const uint8_t *iphdr, int ip_hl, int h_len, const uint8_t * end, const char* func)
{
	if ((iphdr + ip_hl + h_len) > end)
	{
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			"%s(): ip payload not inside packet (pktsz %d, iphsz %d, payloadsz %d)", func,
			(int)(end - iphdr), ip_hl, h_len);
		return -1;
	}

	return 0;
}
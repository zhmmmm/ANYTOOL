#pragma once
#include <pcap.h>
#include <Packet32.h>
#include <WinSock2.h>

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")

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

typedef struct libnet_context libnet_t;

class Libnet
{

public:
	libnet_t *libnet_Init(int Type, char *Device, char *err_buf);

	void libnet_Destroy(libnet_t *libnet);
private:
	void libnet_Clear_Packet(libnet_t *libnet);
	int libnet_Open_Raw4(libnet_t *libnet);
};

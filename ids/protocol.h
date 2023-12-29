#pragma once
#include <pcap.h>

/* IP Addresss Structure */
typedef struct _ip_addr ip_addr;
struct _ip_addr {
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
};


/* MAC Addresss Structure */
typedef struct _mac_addr mac_addr;
struct _mac_addr {
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
	unsigned char byte5;
	unsigned char byte6;
};


/* Ethernet Header Structure */
#pragma pack(push, 1)
typedef struct _ether_header ether_header;
struct _ether_header {
	mac_addr dst; /* Destination MAC address */
	mac_addr src; /* Source MAC address */
	unsigned short type; /* Type(1byte) & Length(1byte) */
};
#pragma pack(pop)

/* TYPE Field */
#define ETHERNET_IP 0x0800
#define ETHERNET_ARP 0x0806
#define ETHERNET_RARP 0x0835


/* ARP Header Structure */
typedef struct _arp_header arp_header;
struct _arp_header {
	unsigned short hard; /*Hardware type */
	unsigned short pro; /* Protocol type */
	unsigned char hlen; /* Hardware address length */
	unsigned char plen; /* Protocol address length */
	unsigned short op; /* Opcode */
	mac_addr sha; /* Source hardware address(mac address) */
	ip_addr spa; /* Source protocol address(ip address) */
	mac_addr dha; /* Destination hardware address(mac address) */
	ip_addr dpa; /* Destination protocol address(ip address) */
};


/* IP Header Structure */
typedef struct _ip_header ip_header;
struct _ip_header {
	unsigned char ver_ihl; /* Version(4bits) & Internet header length(4bits) */
	unsigned char tos; /* Type of service */
	unsigned short tlen; /* Total length */
	unsigned short id; /* Identification */
	unsigned short off; /* Flags(3bits) & Fargment offset(13bits) */
	unsigned char ttl; /* Time to live */
	unsigned char pro; /* Protocol */
	unsigned short checksum; /* Header Checksum */
	ip_addr src; /* Source address */
	ip_addr dst; /* Destination address */
};

/* Protocol Field */
#define IP_ICMP 0x0001
#define IP_IGMP 0x0002
#define IP_TCP 0x0006
#define IP_UDP 0x0011


/* ICMP Header Structure */
typedef struct _icmp_header icmp_header;
struct _icmp_header {
	unsigned char type; /* Type */
	unsigned char code; /* Code */
	unsigned short checksum; /* Checksum */
	unsigned short id; /* Identifier */
	unsigned short seq_num; /* Sequence number */
};

/* TYPE Field */
#define ICMP_ECHO_REP 0 /* Echo reply */
#define ICMP_ECHO_REQ 8 /* Echo request */


/* TCP Header Structure */
typedef struct _tcp_header tcp_header;
struct _tcp_header {
	unsigned short sport; /* Source port */
	unsigned short dport; /* Destination port */
	unsigned int seq_num; /* Sequence number */
	unsigned int ack_num; /* Acknowledgement number */
	unsigned short hlen_flags; /* Header length(4bits) & Flags(12bits) */
	unsigned short win_size; /* Window size */
	unsigned short checksum; /* Checksum */
	unsigned short urgent_ptr; /* Urgent Pointer*/
};

/* Port Field */
#define TCP_FTP 20
#define TCP_SSH 22
#define TCP_TELNET 23
#define TCP_SMTP 25
#define TCP_HTTP 80
#define TCP_POP3 110
#define TCP_IMAP4 143
#define TCP_HTTPS 443

/* UDP Header Structure */
typedef struct _udp_header udp_header;
struct _udp_header {
	unsigned short sport; /* Source port */
	unsigned short dport; /* Destination port */
	unsigned short tlen; /* Total length*/
	unsigned short checksum; /* Checksum */
};
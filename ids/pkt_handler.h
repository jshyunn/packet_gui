#pragma once
#include <pcap.h>

/* Prototype of the Packet Handler */
void packet_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void frame_handler(FILE* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ether_handler(FILE* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ip_handler(FILE* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void arp_handler(FILE* save_file, const u_char* pkt_data);
void rarp_handler(FILE* save_file, const u_char* pkt_data);
void icmp_handler(FILE* save_file, const u_char* pkt_data);
void tcp_handler(FILE* save_file, const u_char* pkt_data);
void udp_handler(FILE* save_file, const u_char* pkt_data);
void data_handler(FILE* save_file, const u_char* pkt_data);
void dispatcher_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
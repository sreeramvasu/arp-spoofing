/*
Name: arp.h
Purpose: Necessary headers for arp.c
Author: Sreeram Vasudevan

*/



#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define DEF_ETH_DEV "eth0"
#define SPOOFED_MAC "00:0c:29:4e:52:96"
#define GATEWAY_MAC "00:50:56:f4:d7:95" 
#define GATEWAY_IP "\xc0\xa8\xe9\x02"

#define NUM_PACKETS 500
#define TIME_OUT 1000
#define PROMISC 1

#define ETH_HEADER_LEN 14
#define SNAP_LEN 1518

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

#define ARP_PROTOCOL 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct Ethernet_Header {
  
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	unsigned short protocol;
};

struct ARP_Header {

	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_addr_len;
	unsigned char protocol_addr_len;
	unsigned short opcode;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];
};

void set_filter_expr(char*, char*);
void process_device(char*, char*, char*, struct bpf_program, bpf_u_int32, char*);
void process_packet(u_char*, const struct pcap_pkthdr*, const u_char*);

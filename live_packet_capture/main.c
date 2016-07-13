#include <stdio.h>
#include <libnet.h>
#include <pcap.h>

#include "./modules/device.h"
#include "./modules/network.h"

const int NONPROMISCUOUS = 1;

inline void ptr_err(char * );
void packet_handler(unsigned char * , const struct pcap_pkthdr * , const unsigned char *);

int main(int argc, char **argv)
{
	struct _SDeviceInformation device;
	char err_msg[PCAP_ERRBUF_SIZE];
	pcap_t * pcap_handle; 
	int err;
	
	device.name = pcap_lookupdev(err_msg);
	if ( !device.name )
	{
		ptr_err(err_msg);
	}	
	
	if( pcap_lookupnet(device.name, &device.ip, &device.mask, err_msg) )
	{
		ptr_err(err_msg);	
	}
	ptr_to_device(device);

	pcap_handle = pcap_open_live(device.name, BUFSIZ, NONPROMISCUOUS, 1000, err_msg);
	if( !pcap_handle )
	{
		ptr_err(err_msg);
	}
	
	err = pcap_loop(pcap_handle, 0, packet_handler, NULL);
	
	if( err == -1 )
	{
		return -1;
	}
	pcap_close(pcap_handle);
	return 0;
}

void ptr_err(char * err_msg)
{	
	printf("%s\n", err_msg);
	exit(1);
}

void packet_handler(unsigned char * u, const struct pcap_pkthdr * header, const unsigned char * packet)
{	
	const struct libnet_udp_hdr * udp_hdr;
	const struct libnet_tcp_hdr * tcp_hdr; 
	const struct libnet_ipv4_hdr * ip_hdr;
	const struct libnet_ethernet_hdr * eth_hdr;
	int type, ip_hdr_len;	
	

	printf("\n\n ===== START ===== \n");
	if( header->caplen < LIBNET_ETH_H ) // ethernet header 
	{
		return ;
	}

	eth_hdr = (const struct libnet_ethernet_hdr *)packet;
	type = ntohs(eth_hdr->ether_type);
	printf("[+] Src MAC : %s\n", mac_to_str(eth_hdr->ether_shost));
	printf("[+] Dest MAC : %s\n", mac_to_str(eth_hdr->ether_dhost));
	printf("[+] Ethernet Type : %s\n", eth_to_type(type));
	
	if( type == ETHERTYPE_IP )
	{
		if( header->caplen < LIBNET_IPV4_H + LIBNET_ETH_H ) // IP Header
		{
			return ;
		}	
		
		// header data
		ip_hdr = (const struct libnet_ipv4 *)(packet + LIBNET_ETH_H);
		ip_hdr_len = ip_hdr->ip_hl << 2;
		type = ip_hdr->ip_p;

		if( ip_hdr->ip_v != 4 || ip_hdr_len < LIBNET_IPV4_H )
		{
			return ;
		}
		printf("[+] Src IP : %s\n", ip_to_str(ip_hdr->ip_src.s_addr));
		printf("[+] Dst IP : %s\n", ip_to_str(ip_hdr->ip_dst.s_addr));	
		printf("[+] IP Protocol : %s\n", ip_to_type(type),type);
		switch( ip_hdr->ip_p )
		{
			case TCP_PROTOCOL:
				if( header->caplen < (ip_hdr_len + LIBNET_ETH_H + LIBNET_TCP_H))
				{
					return ;
				}	
				tcp_hdr = (const struct libnet_tcp_hdr *)(((unsigned char *)ip_hdr) + ip_hdr_len);
				printf("[+] Src PORT : %d\n", ntohs(tcp_hdr->th_sport));
				printf("[+] Dst PORT : %d\n", ntohs(tcp_hdr->th_dport));	
				break;
		case UDP_PROTOCOL:
				if( header->caplen < (ip_hdr_len + LIBNET_ETH_H + LIBNET_UDP_H))
				{
					return ;
				}
				udp_hdr = (const struct libnet_udp_hdr *)(((unsigned char*)ip_hdr) + ip_hdr_len);
				printf("[+] Src PORT : %d\n", ntohs(udp_hdr->uh_sport));
				printf("[+] Dst PORT : %d\n", ntohs(udp_hdr->uh_dport));	
				break;	
			default:
				return ;
		}			
	}
	return ;
}

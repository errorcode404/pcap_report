#include "network.h"

const char * ip_to_type(short int type)
{
	switch(type)
	{
		case TCP_PROTOCOL:
			return "TCP";
		case UDP_PROTOCOL:
			return "UDP";
		case ICMP_PROTOCOL:
			return "ICMP";
		default:
			return "?"; 
	}
}

const char * eth_to_type(short int type)
{
	switch(type)
	{
		case ETHERTYPE_IP:
			return "IPv4";
		case ETHERTYPE_ARP:
			return "ARP";
		default:
			return "?";
	}
} 

char * mac_to_str(const unsigned char mac_address[6])
{
	static unsigned char str[20];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);	
	return str;
}
char * ip_to_str(unsigned int ip_address)
{
	struct sockaddr_in addr;
	addr.sin_addr.s_addr = ip_address;
	return inet_ntoa(addr.sin_addr);
}

#pragma once
#include <libnet.h>	
#include <arpa/inet.h>
#include <stdio.h>

#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

const char * eth_to_type(short int);
char * ip_to_str(unsigned int);
char * mac_to_str(const unsigned char[6]);

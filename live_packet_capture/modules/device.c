#include "device.h"
#include "network.h"

void ptr_to_device(struct _SDeviceInformation device)
{

	printf("[+] Device : %s\n", device.name);	
	printf("[+] IP     : %s\n", ip_to_str(device.ip));	
	printf("[+] NetMask: %s\n", ip_to_str(device.mask));	

}


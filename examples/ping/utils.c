#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <rte_mbuf.h>
#include <unistd.h>

#include "ping.h"
/* *************************************** */

uint32_t get_ipaddrs(char *device)
{
 int fd;
 struct ifreq ifr;
 struct in_addr addr;

 fd = socket(AF_INET, SOCK_DGRAM, 0);

 /* I want to get an IPv4 IP address */
 ifr.ifr_addr.sa_family = AF_INET;

 /* I want IP address attached to "device" */
 strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

 ioctl(fd, SIOCGIFADDR, &ifr);

 close(fd);

 addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
 /* display result */
 return *(uint32_t*)&addr;
}

uint32_t rte_inet_addr(const char *cp)
{
	return inet_addr(cp);
}
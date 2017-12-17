#ifndef __PING_H__
#define __PING_H__

extern uint32_t get_ipaddrs(char *device);
extern uint32_t rte_inet_addr(const char *cp);
extern void arp_icmp_process(uint8_t port);
extern void build_arp_echo_xmit(struct rte_mempool *pool, uint8_t port, uint32_t dest_ip);
extern void build_icmp_echo_xmit(struct rte_mempool *pool, uint8_t port, uint32_t dest_ip, uint16_t id, uint16_t seq);

#endif
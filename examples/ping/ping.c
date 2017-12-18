/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <net/if.h>
#include <unistd.h>

#include "ping.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

uint32_t dst_ip = 0;
uint32_t nic_ip = 0;
static struct rte_mempool *mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { 
		.mq_mode = ETH_MQ_RX_DCB,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		},
		.txmode = {
		.mq_mode = ETH_MQ_TX_DCB,
	},
};

struct ether_addr nic_addr;
struct ether_addr dst_addr;
struct ether_addr null_addr = 
	{.addr_bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

uint32_t icmp_reached =0;
uint64_t icmp_reached_tick;
uint16_t curr_seq = 0;
typedef unsigned long  u_long;

/* *************************************** */

static char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals) {
  uint32_t a1 = ((u_long)val / 1000000000) % 1000;
  uint32_t a = ((u_long)val / 1000000) % 1000;
  uint32_t b = ((u_long)val / 1000) % 1000;
  uint32_t c = (u_long)val % 1000;
  uint32_t d = (uint32_t)((val - (u_long)val)*100) % 100;

  if(add_decimals) {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u.%02d", a1, a, b, c, d);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u.%02d", a, b, c, d);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u.%02d", b, c, d);
    } else
      snprintf(buf, buf_len, "%.2f", val);
  } else {
    if(val >= 1000000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u'%03u", a1, a, b, c);
    } else if(val >= 1000000) {
      snprintf(buf, buf_len, "%u'%03u'%03u", a, b, c);
    } else if(val >= 100000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else if(val >= 1000) {
      snprintf(buf, buf_len, "%u'%03u", b, c);
    } else
      snprintf(buf, buf_len, "%u", (unsigned int)val);
  }

  return(buf);
}


static double ticks_to_us(uint64_t dtick,const uint64_t hz){
  return ((double) 1000000 /* us */) / ( hz / dtick );
}

/* ping.c: measures the round-trip time. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}


/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive arp or icmp packets on a port and reply.
		 */
		for (port = 0; port < nb_ports; port++) {
			arp_icmp_process(port);
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	uint8_t portid, i;
	int max_ping_times = 3;
	char real_device[IFNAMSIZ]={'\0'}, *pname, *dst, *times, buf1[64];

	for(i=0; i<argc; i++)
	{
		pname = strstr(argv[i], "iface=");
		if(pname) {
				snprintf(real_device, sizeof(real_device), "%s", pname+strlen("iface="));
				break;
		}
	}

	for(i=0; i<argc; i++)
	{
		dst = strstr(argv[i], "dest=");
		if(dst) {
				dst_ip = rte_inet_addr(dst+strlen("dest="));
				break;
		}
	}

	for(i=0; i<argc; i++)
	{
		times = strstr(argv[i], "times=");
		if(times) {
				max_ping_times = atoi(times+strlen("times="));
				break;
		}
	}	

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be one\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	rte_eth_macaddr_get(0, &nic_addr);

	nic_ip = get_ipaddrs(real_device);
	if(!nic_ip) {
			printf("cannot get primary address from nic %s\n", real_device);
			exit(0);
	}

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	int slave_core_id = rte_lcore_id();

	/* check state of lcores */
	RTE_LCORE_FOREACH_SLAVE(slave_core_id) {
	if (lcore_config[slave_core_id].state != WAIT)
		return -EBUSY;
	}
	/* start lcore main on core != master_core - ARP and icmp process thread */
	slave_core_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);
	if ((slave_core_id >= RTE_MAX_LCORE) || (slave_core_id == 0))
		return -EPERM;

	printf("Starting lcore_main on core %d:%d Our IP:%d.%d.%d.%d CPU %fMhz\n",
			slave_core_id,
			rte_eal_remote_launch((lcore_function_t *)lcore_main,
					NULL,
					slave_core_id),
 					nic_ip & 0xFF,
 					(nic_ip>>8) & 0xFF,
 					(nic_ip>>16) & 0xFF,
					(nic_ip>>24) & 0xFF, 
					((double)rte_get_tsc_hz())/(1024*1024)
		);

	if(dst_ip == 0)
			goto mp_wait;

	int retry = 0;
	uint64_t icmp_sended_tick;

	while(1) {

re_start:
    if(retry >= max_ping_times) {
        break;
    }

    if(!memcmp(&dst_addr, &null_addr, ETHER_ADDR_LEN)) {
        build_arp_echo_xmit(mbuf_pool, 0, dst_ip);

        int arp_retry = 0;
        while(arp_retry < 30) {

            if(memcmp(&dst_addr, &null_addr, ETHER_ADDR_LEN))
                break;

            usleep(100);
            arp_retry++;
        }

        if(arp_retry == 30)
        {
            printf("ping timeout no arp get\n");
            retry++;
            goto	re_start;
        }
    }

    build_icmp_echo_xmit(mbuf_pool, 0, dst_ip, ICMP_ID, curr_seq);
    icmp_sended_tick = rte_rdtsc();
    icmp_reached = 0;
    int icmp_retry = 0;
    while(icmp_retry < 30) {

        if(icmp_reached)
            break;

        usleep(100);
        icmp_retry++;
    }

    if(icmp_retry == 30)
    {
        printf("ping timeout no icmp reply\n");
    }
    else
    {
        printf("\nPackets received time diff: %s usec\n", pfring_format_numbers(ticks_to_us(icmp_reached_tick - icmp_sended_tick,rte_get_tsc_hz()), buf1, sizeof(buf1), 1));
    }

    curr_seq++;
    retry++;
	}

mp_wait:
	rte_eal_mp_wait_lcore();

	return 0;
}

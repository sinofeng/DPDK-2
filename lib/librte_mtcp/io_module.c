/* for I/O module def'ns */
#include "io_module.h"
/* for num_devices decl */
#include "config.h"
/* std lib funcs */
#include <stdlib.h>
/* std io funcs */
#include <stdio.h>
/* strcmp func etc. */
#include <string.h>
/* for ifreq struct */
#include <net/if.h>
/* for ioctl */
#include <sys/ioctl.h>
/* for dpdk ethernet functions (get mac addresses) */
#include <rte_ethdev.h>

/* for TRACE_* */
#include "debug.h"
/* for inet_* */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* for getopt() */
#include <unistd.h>
/* for getifaddrs */
#include <sys/types.h>
#include <ifaddrs.h>
/*----------------------------------------------------------------------------*/
io_module_func *current_iomodule_func = &dpdk_module_func;
#define ALL_STRING			"all"
#define MAX_PROCLINE_LEN		1024
#define MAX(a, b) 			((a)>(b)?(a):(b))
#define MIN(a, b) 			((a)<(b)?(a):(b))

/*----------------------------------------------------------------------------*/
int
SetInterfaceInfo(char* dev_name_list)
{
	int eidx = 0;
	int i, j;

	int set_all_inf = (strncmp(dev_name_list, ALL_STRING, sizeof(ALL_STRING))==0);

	TRACE_CONFIG("Loading interface setting\n");

	CONFIG.eths = (struct eth_table *)
			calloc(MAX_DEVICES, sizeof(struct eth_table));
	if (!CONFIG.eths) {
		TRACE_ERROR("Can't allocate space for CONFIG.eths\n");
		exit(EXIT_FAILURE);
	}

	{
		int cpu = CONFIG.num_cores;
		uint32_t cpumask = 0;
		char cpumaskbuf[10];
		char mem_channels[5];
		int ret;
		static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

		/* get the cpu mask */
		for (ret = 0; ret < cpu; ret++)
			cpumask = (cpumask | (1 << ret));
		sprintf(cpumaskbuf, "%X", cpumask);

		/* get the mem channels per socket */
		if (CONFIG.num_mem_ch == 0) {
			TRACE_ERROR("DPDK module requires # of memory channels "
				    "per socket parameter!\n");
			exit(EXIT_FAILURE);
		}
		sprintf(mem_channels, "%d", CONFIG.num_mem_ch);

		/* initialize the rte env first, what a waste of implementation effort!  */
		char *argv[] = {"",
				"-c",
				cpumaskbuf,
				"-n",
				mem_channels,
				"--proc-type=auto",
				""
		};
		const int argc = 6;

		/*
		 * re-set getopt extern variable optind.
		 * this issue was a bitch to debug
		 * rte_eal_init() internally uses getopt() syscall
		 * mtcp applications that also use an `external' getopt
		 * will cause a violent crash if optind is not reset to zero
		 * prior to calling the func below...
		 * see man getopt(3) for more details
		 */
		optind = 0;

		/* initialize the dpdk eal env */
		ret = rte_eal_init(argc, argv);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Invalid EAL args!\n");
		/* give me the count of 'detected' ethernet ports */
		num_devices = rte_eth_dev_count();
		if (num_devices == 0) {
			rte_exit(EXIT_FAILURE, "No Ethernet port!\n");
		}

		/* get mac addr entries of 'detected' dpdk ports */
		for (ret = 0; ret < num_devices; ret++) {
			rte_eth_macaddr_get(ret, &ports_eth_addr[ret]);

			snprintf(CONFIG.eths[ret].dev_name, sizeof(CONFIG.eths[0].dev_name), "dpdk%d", ret);
			CONFIG.eths[ret].ifindex = ret;
			CONFIG.eths[ret].stat_print = 1;
			memcpy(CONFIG.eths[ret].haddr, &ports_eth_addr[ret], ETH_ALEN);
			CONFIG.eths[ret].netmask = htonl(0xffffff00);
			CONFIG.eths[ret].ip_addr = htonl(0xc0a8de00 + ports_eth_addr[ret].addr_bytes[5]);

			CONFIG.eths_num++;
			devices_attached[ret] = ret;
			num_devices_attached++;
			printf("Port %d ip %d.%d.%d.%d\n", ret, 
						CONFIG.eths[ret].ip_addr & 0xFF, 
						CONFIG.eths[ret].ip_addr >> 8 & 0xFF, 
						CONFIG.eths[ret].ip_addr >> 16 & 0xFF, 
						CONFIG.eths[ret].ip_addr >> 24 & 0xFF);
		}

		num_queues = MIN(CONFIG.num_cores, MAX_CPUS);
	}

	CONFIG.nif_to_eidx = (int*)calloc(MAX_DEVICES, sizeof(int));

	if (!CONFIG.nif_to_eidx) {
	        exit(EXIT_FAILURE);
	}

	for (i = 0; i < MAX_DEVICES; ++i) {
	        CONFIG.nif_to_eidx[i] = -1;
	}

	for (i = 0; i < CONFIG.eths_num; ++i) {

		j = CONFIG.eths[i].ifindex;
		if (j >= MAX_DEVICES) {
		        TRACE_ERROR("ifindex of eths_%d exceed the limit: %d\n", i, j);
		        exit(EXIT_FAILURE);
		}

		/* the physic port index of the i-th port listed in the config file is j*/
		CONFIG.nif_to_eidx[j] = i;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
int
FetchEndianType()
{
	char *argv;
	char **argp = &argv;
	/* dpdk_module_func logic down below */
	dpdk_module_func.dev_ioctl(NULL, CONFIG.eths[0].ifindex, DRV_NAME, (void *)argp);
	if (!strcmp(*argp, "net_i40e"))
		return 1;

	return 0;
}
/*----------------------------------------------------------------------------*/

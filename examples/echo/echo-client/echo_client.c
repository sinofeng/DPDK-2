#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>

#include <rte_ethdev.h>
#include <rte_cycles.h>

#include <mtcp_api.h>
#include <netlib.h>
#include <cpu.h>

#define BUFFER_SIZE 1024
#define ECHO_SERVER_IP "192.168.222.160"
#define ECHO_ECHO_PORT 6999
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

static int num_cores;
static int core_limit;

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

int main (int argc, char *argv[]) {
  struct mtcp_conf mcfg;
  char *conf_file;  
  mctx_t mctx;
  int sockid;
  struct sockaddr_in addr;
  char buf[BUFFER_SIZE];
  int ret, o;
	uint64_t one_way_sended_tick, curr_ticks_diff;
  uint64_t max_delay = 0,min_delay=(uint64_t)-1,sum_delay=0;
	int max_echo_times = 3;
	char *p, buf1[64];
	int retry = 0, packets_received = 0;

  num_cores = GetNumCPUs();
  core_limit = num_cores;    

  while (-1 != (o = getopt(argc, argv, "N:f:C:"))) {
    switch(o) {
    case 'N':
      core_limit = mystrtol(optarg, 10);
      if (core_limit > num_cores) {
        on_error("CPU limit should be smaller than the "
               "number of CPUS: %d\n", num_cores);
        return -1;
      } else if (core_limit < 1) {
        on_error("CPU limit should be greater than 0\n");
        return -1;
      }
      /** 
       * it is important that core limit is set 
       * before mtcp_init() is called. You can
       * not set core_limit after mtcp_init()
       */
      mtcp_getconf(&mcfg);
      mcfg.num_cores = core_limit;
      mtcp_setconf(&mcfg);
      break;
    case 'f':
      conf_file = optarg;
      break;
		case 'C':
			max_echo_times = mystrtol(optarg, 10);
			break;
    }
  } 

  if (conf_file == NULL) {
    on_error("mTCP configuration file is not set!\n");
    exit(-1);
  }
  
  ret = mtcp_init(conf_file);
  if (ret) {
    on_error("Failed to initialize mtcp.\n");
    exit(-1);
  }
  
  mtcp_core_affinitize(0);
  mctx = mtcp_create_context(0);
  sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
  if (sockid < 0) 
    on_error("Could not create socket\n");

  addr.sin_family = AF_INET;
  addr.sin_port = htons(ECHO_ECHO_PORT);
  addr.sin_addr.s_addr = inet_addr(ECHO_SERVER_IP);

  printf("connect to %s:%d\n", ECHO_SERVER_IP, ECHO_ECHO_PORT);

  ret = mtcp_connect(mctx, sockid, 
      (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

  if (ret < 0) {
    if (errno != EINPROGRESS) {
      perror("mtcp_connect failed");
      mtcp_close(mctx, sockid);
      return -1;
    }
  }
 
  ret = mtcp_setsock_nonblock(mctx, sockid);
  if (ret < 0) {
    on_error("Failed to set socket in nonblocking mode.\n");
    exit(-1);
  }
 
  while (retry < max_echo_times) {
		int read, write;

		while(1) {
			one_way_sended_tick = rte_get_tsc_hz();
	    write = mtcp_write(mctx, sockid, "12312313", strlen("12312313"));
	    if (write == 0) {
	      on_error("Client write failed\n");
				exit(1);
			} else if (write < 0 && errno == EAGAIN) {
				continue;
			}
		}

    while (1) {
      read = mtcp_recv(mctx, sockid, buf, BUFFER_SIZE, 0);
      if(read == 0) {
        on_error("Client read failed\n");
				exit(1);
      } else if (read < 0 && errno == EAGAIN) {
				continue;
			}
    }

		packets_received++;
		curr_ticks_diff = (rte_get_tsc_hz() - one_way_sended_tick)/2;
		if(curr_ticks_diff > max_delay) max_delay = curr_ticks_diff;
		if(curr_ticks_diff < min_delay) min_delay = curr_ticks_diff;
		sum_delay += curr_ticks_diff;
		
		if(ticks_to_us(curr_ticks_diff, rte_get_tsc_hz()) > 20.0f)
			printf("ping seq %d reply %f us over 20 us, warnnging packet\n", retry, ticks_to_us(curr_ticks_diff, rte_get_tsc_hz()));
  }

  if(packets_received > 0) {
    struct rte_eth_stats stats;
		int i;
  
    const double avg_delay = ((double)sum_delay)/packets_received;
    printf("\nOne-way Packets received: %d\n", packets_received);
    printf("One-way Max delay: %s usec\n", pfring_format_numbers(ticks_to_us(max_delay,rte_get_tsc_hz()), buf1, sizeof(buf1), 1));
    printf("One-way Min delay: %s usec\n", pfring_format_numbers(ticks_to_us(min_delay,rte_get_tsc_hz()), buf1, sizeof(buf1), 1));
    printf("One-way Avg delay: %s usec\n", pfring_format_numbers(ticks_to_us(avg_delay,rte_get_tsc_hz()), buf1, sizeof(buf1), 1));

  	for (i = 0; i < rte_eth_dev_count(); i++) {
  		rte_eth_stats_get(i, &stats);
  		printf("\nPort %d:\n", i);
  		printf("  RX-packets:              %10"PRIu64"    RX-errors: %10"PRIu64
  		       "    RX-bytes: %10"PRIu64"\n",
  		       stats.ipackets, stats.ierrors, stats.ibytes);
  		printf("  RX-errors:  %10"PRIu64"\n", stats.ierrors);
  		printf("  RX-nombuf:               %10"PRIu64"\n",
  		       stats.rx_nombuf);
  		printf("  TX-packets:              %10"PRIu64"    TX-errors: %10"PRIu64
  		       "    TX-bytes: %10"PRIu64"\n",
  		       stats.opackets, stats.oerrors, stats.obytes);
  	}
  }

  return 0;
}

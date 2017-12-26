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

#include <mtcp_api.h>

#define BUFFER_SIZE 1024
#define ECHO_SERVER_IP "192.168.222.160"
#define ECHO_ECHO_PORT 6999
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

static int num_cores;
static int core_limit;

int main (int argc, char *argv[]) {
	struct mtcp_conf mcfg;
	char *conf_file;	
  mctx_t mctx;
  int sockid;
  struct sockaddr_in addr;
  char buf[BUFFER_SIZE];
  int ret, o;

	num_cores = GetNumCPUs();
	core_limit = num_cores;    

	while (-1 != (o = getopt(argc, argv, "N:f:"))) {
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
  if (sockid < 0) on_error("Could not create socket\n");

  addr.sin_family = AF_INET;
  addr.sin_port = htons(ECHO_ECHO_PORT);
  addr.sin_addr.s_addr = inet_addr(ECHO_SERVER_IP);

  printf("connect to %s:%d\n", ECHO_SERVER_IP, ECHO_ECHO_PORT);

	ret = mtcp_setsock_nonblock(mctx, sockid);
	if (ret < 0) {
		on_error("Failed to set socket in nonblocking mode.\n");
		exit(-1);
	}

	ret = mtcp_connect(mctx, sockid, 
			(struct sockaddr *)&addr, sizeof(struct sockaddr_in));

	if (ret < 0) {
		if (errno != EINPROGRESS) {
			perror("mtcp_connect failed");
			mtcp_close(mctx, sockid);
			return -1;
		}
	}
  
  while (1) {
	  ret = mtcp_write(mctx, sockid, "12312313", strlen("12312313"));
	  if (ret < 0) on_error("Client write failed\n");

    while (1) {
      int read = mtcp_recv(mctx, sockid, buf, BUFFER_SIZE, 0);
	  if(read == 0) {
		  on_error("Client read failed\n");
		  break;
	  } else {
		  continue;
	  }
    }
  }

  return 0;
}
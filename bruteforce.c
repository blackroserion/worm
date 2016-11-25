#include "bruteforce.h"

int bruteforce(char *dest, unsigned int maxlength) {
  static char guess[MAX_PASSWORD_LENGTH];
  static unsigned char guess_map[MAX_PASSWORD_LENGTH];
  static int guess_length = 0;
  char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  unsigned int nchars, i;

  nchars = strlen(characters);

  if(guess_length == 0) {
    for(i = 0; i < maxlength; ++i) {
      guess[i] = '\0';
      guess_map[i] = 0;
    }

    guess[0] = characters[0];
    guess_length = 1;
  } else {
    if(guess_length > maxlength) {
      guess_length = 0;
      return 0;
    }

    guess_map[0]++;

    for(i = 0; guess_map[i] > nchars - 1; ++i) {
      guess_map[i] = 0;
      guess_map[i + 1]++;
    }

    if(i > guess_length) {
      ++guess_length;
    }

    for(i = 0; i < guess_length; ++i) {
      guess[i] = characters[guess_map[i]];
    }
  }

  strncpy(dest, guess, maxlength);
  return 1;
}

int ftp_try_login(const char *address, unsigned int port, const char *user, const char *password) {
  char answer[128];
  char request[32];
  struct sockaddr_in addr;
  struct timeval recv_timeout;
  static int tries = 0;
  static int sock = 0;

  if(sock == 0 || tries == 0) {
    recv_timeout.tv_sec = 2;
    recv_timeout.tv_usec = 0;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address);  
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("ftp_try_login (socket)");
      return 0;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof recv_timeout) == -1) {
        perror("ftp_try_login (setsockopt)");
        close(sock);
        return 0;
    }

    if(connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
      perror("fty_try_login (connect)");
      close(sock);
      return 0;
    }

    recv(sock, answer, sizeof answer, 0);
    if(strncmp(answer, "220", 3) != 0) {
      close(sock);
      sock = 0;
      return 0;
    }

    tries = FTP_LOGIN_TRIES;
  }

  snprintf(request, sizeof request, "USER %s\n", user);
  if(send(sock, request, sizeof request, 0) < 0) {
    perror("fty_try_login (send)");
    return 0;
  }
  
  recv(sock, answer, sizeof answer, 0);
  if(strncmp(answer, "331", 3) != 0) {
    return 0;
  }

  snprintf(request, sizeof request, "PASS %s\n", password);
  if(send(sock, request, sizeof request, 0) < 0) {
    perror("fty_try_login (send)");
    return 0;
  }

  recv(sock, answer, sizeof answer, 0);
  if(strncmp(answer, "230", 3) != 0) {
    return 0;
  }

  return sock;
}

#ifdef BRUTEFORCE_MAIN

int main(int argc, const char *argv[]) {
  char dest[MAX_PASSWORD_LENGTH];

  while(bruteforce(dest, sizeof dest)) {
    fprintf(stdout, "%s\n", dest);
    usleep(500);
  }

  return 0;
}

#endif

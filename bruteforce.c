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
/*
int main(int argc, const char *argv[]) {
  char dest[MAX_PASSWORD_LENGTH];

  while(bruteforce(dest, sizeof dest)) {
    fprintf(stdout, "%s\n", dest);
    usleep(500);
  }

  return 0;
}
*/

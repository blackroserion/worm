#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <bsd/md5.h>

#define MAX_PASSWORD_LENGTH    8

int bruteforce(char *dest, unsigned int maxlength);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <bsd/md5.h>

#define MAX_PASSWORD_LENGTH    8
#define FTP_LOGIN_TRIES        5

int bruteforce(char *dest, unsigned int maxlength);
int ftp_try_login(const char *address, unsigned int port, const char *user, const char *password);

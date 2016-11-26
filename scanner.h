#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Buffer length */
#define BUFFER_LENGTH     256

/* Request string */
#define MAGIC_STRING      "HEAD / HTTP/1.1\n\n"

/* Connect timeout (seconds) */
#define CONNECT_TIMEOUT   800

/* Recv timeout (seconds) */
#define RECV_TIMEOUT      4

/* Scan table */
struct scan_table {
  char address[32];
  char banner[64];
  unsigned int port;
  struct scan_table *next;
};

/* Pseudo header for checksum calculation */
struct pseudo_header {
  unsigned int source_address;
  unsigned int dest_address;
  unsigned char placeholder;
  unsigned char protocol;
  unsigned short tcp_length;
};

in_addr_t get_interface_address(const char *interface);
char *strfind(const char *string, char character);
unsigned short csum(unsigned short *data, unsigned int length);
void range_scan(const char *range, unsigned int *first, unsigned int *last);
void scan_port(const char *interface, const char *address, unsigned int port, unsigned char use_raw_socket, unsigned char verbose, struct scan_table **table);
struct scan_table *scanner(const char *range, const char *ports, const char *interface, int use_raw_socket, int verbose);

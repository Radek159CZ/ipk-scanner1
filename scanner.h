#ifndef SCANNER_H
#define SCANNER_H

//#include <netinet/ip.h>
//#include <netinet/tcp.h>
//#include <arpa/inet.h>

//
struct config {
    char *iface;
    char *host;
    int tcp_ports[1000]; 
    int tcp_count;
    int udp_ports[1000];
    int udp_count; 
    int timeout;
    unsigned int src_ip;
    int is_ipv6;
    unsigned char src_ipv6[16];
};


struct addrinfo* resolve_hostname(const char *hostname);
unsigned short checksum(unsigned short *ptr, int nbytes);


void run_tcp_scanner(struct config *cfg);
void run_udp_scanner(struct config *cfg);

#endif
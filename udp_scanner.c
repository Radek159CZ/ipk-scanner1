#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/time.h>


#include "scanner.h"

//
struct udp_pseudo_header {
    unsigned int source;
    unsigned int destination;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short length;
};

//
void run_udp_scanner(struct config *cfg) {
    char *target_ip = cfg->host;
    if (target_ip == NULL) return;


    int sd_send; 
    int sd_recv;

    if (cfg->is_ipv6) {
        sd_send = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
        sd_recv = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    else {
        sd_send = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        sd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }

    if (sd_send < 0 || sd_recv < 0) {
        perror("Error: Raw sockets failed (UDP)");
        return;
    }

    struct timeval tv;
    tv.tv_sec = cfg->timeout / 1000;
    tv.tv_usec = (cfg->timeout % 1000) * 1000;
    setsockopt(sd_recv, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    if (!cfg->is_ipv6) {
        int one = 1;
        setsockopt(sd_send, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }

    for (int i = 0; i < cfg->udp_count; i++) {
        int state = 1;

        for(int retry = 0; retry < 2; retry++) {
            
            // ICMP Receive
            char packet[4096];
            memset(packet, 0, 4096);
            

            if (cfg->is_ipv6) {
                struct udphdr *udph = (struct udphdr *) packet;
                udph->source = htons(12345);
                udph->dest = htons(cfg->udp_ports[i]);
                udph->len = htons(sizeof(struct udphdr));
                udph->check = 0;

                struct sockaddr_in6 dest6;
                memset(&dest6, 0, sizeof(dest6));
                dest6.sin6_family = AF_INET6;
                inet_pton(AF_INET6, target_ip, &dest6.sin6_addr);
                sendto(sd_send, packet, sizeof(struct udphdr), 0, (struct sockaddr *)&dest6, sizeof(dest6));
            }
            else {
                struct iphdr *iph = (struct iphdr *) packet;
                struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));

                iph->ihl = 5; iph->version = 4; iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
                iph->protocol = IPPROTO_UDP; iph->saddr = cfg->src_ip; iph->daddr = inet_addr(target_ip);
                iph->ttl = 64; iph->check = checksum((unsigned short *)packet, 20);

                udph->source = htons(12345);
                udph->dest = htons(cfg->udp_ports[i]);
                udph->len = htons(sizeof(struct udphdr));

                struct udp_pseudo_header psh;
                psh.source = iph->saddr; psh.destination = iph->daddr;
                psh.placeholder = 0; psh.protocol = IPPROTO_UDP;
                psh.length = htons(sizeof(struct udphdr));
                char *psig = malloc(sizeof(struct udp_pseudo_header) + sizeof(struct udphdr));
                memcpy(psig, &psh, sizeof(struct udp_pseudo_header));
                memcpy(psig + sizeof(struct udp_pseudo_header), udph, sizeof(struct udphdr));
                udph->check = checksum((unsigned short *)psig, sizeof(struct udp_pseudo_header) + sizeof(struct udphdr));
                free(psig);

                struct sockaddr_in dest4;
                dest4.sin_family = AF_INET; dest4.sin_addr.s_addr = iph->daddr;
                sendto(sd_send, packet, iph->tot_len, 0, (struct sockaddr *)&dest4, sizeof(dest4));
            }

            // ICMP Receive
            char recv_buf[65536];
            int res = recvfrom(sd_recv, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
            if (res > 0) {
                if (cfg->is_ipv6) {
                    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)recv_buf;
                    
                    if (icmp6->icmp6_type == 1 && icmp6->icmp6_code == 4) {
                        state = 0;
                        break;
                    }

                }
                else {
                    struct iphdr *ri = (struct iphdr *)recv_buf;
                    struct icmphdr *icmph = (struct icmphdr *)(recv_buf + (ri->ihl * 4));
                    
                    if (icmph->type == 3 && icmph->code == 3) {
                        state = 0;
                        break;
                    }
                }

            }
        }

        printf("%s %d udp %s\n", target_ip, cfg->udp_ports[i], state==1?"open":"closed");
    }
    
    close(sd_send);
    close(sd_recv);
}
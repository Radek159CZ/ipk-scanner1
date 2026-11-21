#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>


#include "scanner.h"

//
struct tcp_pseudo_header {
    unsigned int source;
    unsigned int destination;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short length;
};

//
void run_tcp_scanner(struct config *cfg) {
    char *target_ip = cfg->host;
    if (target_ip == NULL) return;

    int sd;
    if (cfg->is_ipv6) {
        sd = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    }
    else{
        sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    }

    if (sd < 0) {
        perror("Error: Raw socket failed (try running with sudo)");
        return;
    }

    struct timeval tv;
    tv.tv_sec = cfg->timeout / 1000;
    tv.tv_usec = (cfg->timeout % 1000) * 1000;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    if (!cfg->is_ipv6) {
        int one = 1;
        setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }

    for (int i = 0; i < cfg->tcp_count; i++) {
        int state = -1;

        for(int retry = 0; retry < 2; retry++) {
            char packet[4096];
            memset(packet, 0, 4096);

            struct iphdr *iph = (struct iphdr *) packet;
            struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));

            // Build IP Header
            iph->ihl = 5;
            iph->version = 4;
            iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
            iph->protocol = IPPROTO_TCP;
            iph->saddr = cfg->src_ip; 
            iph->daddr = inet_addr(target_ip);
            iph->ttl = 255;
            iph->id = htons(54321 + i + retry);
            iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

            // Build TCP SYN Header
            tcph->source = htons(12345);
            tcph->dest = htons(cfg->tcp_ports[i]);
            tcph->seq = htonl(0);
            tcph->doff = 5;
            tcph->syn = 1;      
            tcph->window = htons(5840);
            tcph->check = 0;    

            struct tcp_pseudo_header psh;
            psh.source = iph->saddr;
            psh.destination = iph->daddr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.length = htons(sizeof(struct tcphdr));

            int psize = sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr);
            char *pseudogram = malloc(psize);
            memcpy(pseudogram, (char*) &psh, sizeof(struct tcp_pseudo_header));
            memcpy(pseudogram + sizeof(struct tcp_pseudo_header), tcph, sizeof(struct tcphdr));
            tcph->check = checksum((unsigned short*) pseudogram, psize);
            free(pseudogram);

            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = iph->daddr;

            if (cfg->is_ipv6) {
                struct sockaddr_in6 dest6;
                memset(&dest6, 0, sizeof(dest6));
                dest6.sin6_family = AF_INET6;
                inet_pton(AF_INET6, target_ip, &dest6.sin6_addr);
                sendto(sd, tcph, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest6, sizeof(dest6));
            }
            else {
                sendto(sd, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
            }

            char recv_buf[65536];
            

            while (1) {
                int res = recvfrom(sd, recv_buf, 65536, 0, NULL, NULL);
                if (res < 0) break; 


                struct tcphdr *tcph_res;
                if (cfg->is_ipv6) {
                    tcph_res = (struct tcphdr *)recv_buf;
                } else {
                    struct iphdr *iph_res = (struct iphdr *)recv_buf;
                    tcph_res = (struct tcphdr *)(recv_buf + (iph_res->ihl * 4));
                }

                //
                if (ntohs(tcph_res->dest) == 12345 && (tcph_res->ack || tcph_res->rst)) {
                    if (tcph_res->syn && tcph_res->ack) state = 1;
                    else if (tcph_res->rst) state = 0;
                    break;
                }
            }
            if (state != -1) {
                break;
            }
        }

        if (state == 1){ 
            printf("%s %d tcp open\n", target_ip, cfg->tcp_ports[i]);
        }
        else if (state == 0) {
            printf("%s %d tcp closed\n", target_ip, cfg->tcp_ports[i]);
        }
        else {
            printf("%s %d tcp filtered\n", target_ip, cfg->tcp_ports[i]);
        }
    }
    
    close(sd);
}
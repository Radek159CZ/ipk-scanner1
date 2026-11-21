// IPK PROJEKT 1
// Autor: Radek Trebula


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <netdb.h>      
#include <arpa/inet.h>  
#include <sys/ioctl.h>  
#include <net/if.h>
#include <ifaddrs.h>


#include "scanner.h"


// 
void parse_p(char *arg, int *ports, int *count) {
    
    char *dash = strchr(arg, '-');
    if (dash != NULL) {
        int start = atoi(arg);
        int end = atoi(dash + 1);
        
        if (start > end || start < 1 || end > 65535) {
            fprintf(stderr, "Error: Invalid port range %d-%d\n", start, end);
            return;
        }
        for (int i = start; i <= end && (*count) < 1000; i++) {
            ports[(*count)++] = i;
        }
    } else {
       
        char *token = strtok(arg, ",");
        while (token != NULL && (*count) < 1000) {
            int p = atoi(token);
            if (p >= 1 && p <= 65535) {
                ports[(*count)++] = p;
            }
            token = strtok(NULL, ",");
        }
    }
}

int main(int argc, char **argv) {
    struct config cfg = {NULL, NULL, {0}, 0, {0}, 0, 1000, 0, 0, {0}};
    int opt;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: ./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT] [-h | --help]\n");
            return 0;
        }
    }

    if (argc == 2 && strcmp(argv[1], "-i") == 0) {
        struct ifaddrs *ifaddr;
        
        // 
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return 1;
        }

        // 
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            
            if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
                printf("%s\n", ifa->ifa_name);
            }
        }
        freeifaddrs(ifaddr);
        return 0;
    }
    
    //int timeout = 1000;

    while ((opt = getopt(argc, argv, "i:t:u:w:h")) != -1) {
        switch (opt) {
            case 'i': cfg.iface = optarg; break;
            case 't': 
                parse_p(optarg, cfg.tcp_ports, &cfg.tcp_count); 
                break;   
            case 'u': 
                parse_p(optarg, cfg.udp_ports, &cfg.udp_count);
                break; 
            case 'w': cfg.timeout = atoi(optarg); break;
            case 'h': 
                printf("Usage: ./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT] [-h | --help]\n");
                return 0;
            default:
                return 1;
        }
    }

    //
    if (optind < argc) cfg.host = argv[optind];

    if (!cfg.iface || !cfg.host) {
        fprintf(stderr, "Error: Interface and Host are required. See -h for help.\n");
        return 1;
    }

    // 
    struct ifaddrs *ifaddr, *ifa;
    int found_v4 = 0;
    if (getifaddrs(&ifaddr) == -1) { 
        perror("getifaddrs"); 
        return 1; 
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        // Hledáme IPv4 adresu pro rozhraní zadané v -i
        if (strcmp(ifa->ifa_name, cfg.iface) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            cfg.src_ip = sin->sin_addr.s_addr;
            found_v4 = 1;
            break;
        }
    }
    freeifaddrs(ifaddr);

    if (strcmp(cfg.iface, "lo") == 0) {
        cfg.src_ip = inet_addr("127.0.0.1");
    } else if (!found_v4) {
        fprintf(stderr, "Error: Could not find IPv4 address for interface %s\n", cfg.iface);
        return 1;
    }

    // DNS
    struct addrinfo *targets = resolve_hostname(cfg.host);
    if (targets == NULL) {
        return 1; 
    }

    //
    for (struct addrinfo *rp = targets; rp != NULL; rp = rp->ai_next) {
        char target_ip_str[INET6_ADDRSTRLEN];
        
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
            inet_ntop(AF_INET, &addr->sin_addr, target_ip_str, sizeof(target_ip_str));
            cfg.is_ipv6 = 0;
        }
        else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)rp->ai_addr;
            inet_ntop(AF_INET6, &addr->sin6_addr, target_ip_str, sizeof(target_ip_str));
            cfg.is_ipv6 = 1;
        }
        else continue;

        cfg.host = target_ip_str;

        if (cfg.tcp_count > 0) {
            run_tcp_scanner(&cfg);
        }
        if (cfg.udp_count > 0) {
            run_udp_scanner(&cfg);
        }

    }
    freeaddrinfo(targets);

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <time.h>

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   // icmp header
#include <netinet/udp.h>       // udp header
#include <netinet/tcp.h>       // tcp header
#include <netinet/ip.h>        // ip header
#include <netinet/in.h>        // sockaddr_in
#include <linux/if.h>

#include "mydump.h"
#include "debug.h"

static void sniffinterface(pcap_t *handle, char *searchstring);
static void readdump();
static bool interfaceexists(const char *interface);
static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static void printeth(const u_char *packet, size_t length);
static size_t printip(const u_char *packet, size_t length, char *srcip, char *destip);
static void printudp(const u_char* packet, size_t length);
static void printtcp(const u_char* packet, size_t length);
static void printicmp(const u_char* packet, size_t length);
static void printother(const u_char* packet, size_t length);

int main(int argc, char *argv[]) {
    int opt;
    char *expression = NULL;
    char *interface = NULL;
    char *inputfile = NULL;
    char *searchstring = NULL;

    // Iterate through the command line arguments
    while ((opt = getopt(argc, argv, "hi:r:s:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                inputfile = optarg;
                break;
            case 's':
                searchstring = optarg;
                break;
            case 'h':
                USAGE(argv[0], stdout, EXIT_SUCCESS);
                break;
            default: /* '?' */
                USAGE(argv[0], stderr, EXIT_FAILURE);
                break;
        }
    }

    // Check to make sure an interface and a file were not provided.
    if (interface != NULL && inputfile != NULL) {
        fprintf(stderr, "You cannot provide both an interface and an input file.\n");
        USAGE(argv[0], stderr, EXIT_FAILURE);
    }

    // Make sure if a bpf filter was provided, we only have one
    if (optind < argc && (argc - optind) == 1) {
        expression = argv[optind];
    } else {
        error("Too many positional arguments provided.\n");
        error("Expected 1 BPF filter but found %d positional argument(s).\n", argc - optind);
        return EXIT_FAILURE;
    }

    // Do some basic logging for debug
    debug("Search String: %s\n", searchstring);
    debug("Expression: %s\n", expression);

    // Figure out to read the file or read the interface
    if (inputfile == NULL) {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 mask;   /* The netmask of our sniffing device */
        bpf_u_int32 net;    /* The IP of our sniffing device */
        // struct bpf_program fp;

        if (interface == NULL) {
            // No intvoiderface provided; just pick one
            if ((interface = pcap_lookupdev(errbuf)) == NULL) {
                error("%s\n", errbuf);
                return EXIT_FAILURE;
            } else {
                info("Bounded to the default interface %s\n", interface);
            }
        } else {
            if (!interfaceexists(interface)) {
                error("The interface %s does not exist.\n", interface);
                return EXIT_FAILURE;
            }
        }

        // Collect information about the ipaddress and netmask
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            error("%s\n", errbuf);
            net = mask = 0;
        }

        // Create a handle for the live interface
        if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            error("%s\n", errbuf);
            return EXIT_FAILURE;
        }

        // If theres a filter, make the filter
        if (expression != NULL) {
            // TODO: Make the filter
            // TODO: Apply the filter
        }

        // Sniff on the interface
        sniffinterface(handle, searchstring);

        // Close the session
        pcap_close(handle);
    } else {
        readdump();
    }

    return EXIT_SUCCESS;
}

static void sniffinterface(pcap_t *handle, char *searchstring) {
    if (handle == NULL)
        return;
    pcap_loop(handle, -1, callback, (u_char*)searchstring);
}

static void readdump() {
}

static bool interfaceexists(const char *interface) {
    bool exists = false;
    if (interface != NULL) {
        struct ifaddrs *ifaddrs, *ifa;

        // Try to get list of interfaces
        if (getifaddrs(&ifaddrs) == -1) {
            perror("getifaddrs");
            return exists;
        }

        // Iterate through the devices
        for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (strcmp(ifa->ifa_name, interface) == 0 && CHECK_FLAG(ifa->ifa_flags, IFF_UP)) {
                exists = true;
                break;
            }
        }

        // We are done; free the list
        freeifaddrs(ifaddrs);
    }
    return exists;
}

static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // source and destination IP
    // address and port, protocol (TCP, UDP, ICMP, OTHER), and the raw content of the
    // application-layer packet payload
    // Extract the time stamp
    char buffer[256];
    time_t ts = pkthdr->ts.tv_sec;
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&ts));
    printf("%s ", buffer);

    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    // Figure out protocol sensitive information
    switch (iph->protocol) {
        case TYPE_ICMP:
            printicmp(packet, pkthdr->len);
            break;
        case TYPE_UDP:
            printudp(packet, pkthdr->len);
            break;
        case TYPE_TCP:
            printtcp(packet, pkthdr->len);
            break;
        default:
            printother(packet, pkthdr->len);
            break;
    }


    // if (args != NULL) {
    //     if (strstr((char*)packet, (char*)args) == NULL) {
    //         return;
    //     }
    // }
    // // Print out the information about the packet
    // printf("Jacked a packet with length of [%d]\n", pkthdr->len);
}

static void printeth(const u_char *packet, size_t length) {
    // source and destination MAC address
    struct ethhdr *hdr = (struct ethhdr*)packet;
    // Print out the source mac address
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
        hdr->h_source[0],
        hdr->h_source[1],
        hdr->h_source[2],
        hdr->h_source[3],
        hdr->h_source[4],
        hdr->h_source[5]);
    // Print out the destination mac address
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
        hdr->h_dest[0],
        hdr->h_dest[1],
        hdr->h_dest[2],
        hdr->h_dest[3],
        hdr->h_dest[4],
        hdr->h_dest[5]);
    // Print out the ethernet type
    printf("%04x ", ntohs(hdr->h_proto));
    // Print out the packet length
    printf("%5zu ", length);
}

static size_t printip(const u_char *packet, size_t length, char *srcip, char *destip) {
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    // Zero out the structs
    memset(&source, 0, sizeof(struct sockaddr_in));
    memset(&dest, 0, sizeof(struct sockaddr_in));
    // Set values
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    strcpy(srcip, inet_ntoa(source.sin_addr));
    strcpy(destip, inet_ntoa(dest.sin_addr));
    return iph->ihl * 4;
}

static void printudp(const u_char* packet, size_t length) {
    char src[32], dst[32];
    size_t iphdrlen;
    printeth(packet, length);
    iphdrlen = printip(packet, length, src, dst);
    // Now do Specific udp stuff
    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + sizeof(struct ethhdr));
    printf("%15s:%5u > %15s:%5u UDP\n", src, udph->source, dst, udph->dest);
}

static void printtcp(const u_char* packet, size_t length) {
    char src[32], dst[32];
    size_t iphdrlen;
    // Print out eth and ip headers
    printeth(packet, length);
    iphdrlen = printip(packet, length, src, dst);
    // Get port information from tcp packet
    struct tcphdr *tcph = (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
    // Now do Specific tcp stuff
    printf("%15s:%5u > %15s:%5u TCP\n", src, tcph->source, dst, tcph->dest);
}

static void printicmp(const u_char* packet, size_t length) {
    char src[32], dst[32];
    printeth(packet, length);
    printip(packet, length, src, dst);
    // Now do Specific ICMP stuff
    printf("%21s > %21s ICMP\n", src, dst);
}

static void printother(const u_char* packet, size_t length) {
    char src[32], dst[32];
    printeth(packet, length);
    printip(packet, length, src, dst);
    // Now do Specific other stuff
    printf("%21s > %21s OTHER\n", src, dst);
}

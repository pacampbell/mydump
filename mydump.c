#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include <time.h>
#include <signal.h>

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "mydump.h"
#include "debug.h"

static void sniffinterface(pcap_t *handle, char *searchstring);
static bool interfaceexists(const char *interface);
static void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
static void printeth(const u_char *packet, size_t length);
static size_t printip(const u_char *packet, size_t length, char *srcip, char *destip);
static void printudp(const u_char* packet, size_t length);
static void printtcp(const u_char* packet, size_t length);
static void printicmp(const u_char* packet, size_t length);
static void printother(const u_char* packet, size_t length);
static void printpayload(const u_char* packet, size_t length);
static bool searchpacket(const u_char *packet, size_t length, char *search);

// static p

static pcap_t *handle = NULL;

void exithandler(int dummy) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

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
    } else if (optind == argc && (argc - optind) == 0) {
        // NOP
    } else {
        error("Too many positional arguments provided.\n");
        error("Expected 1 BPF filter but found %d positional arguments.\n", argc - optind);
        return EXIT_FAILURE;
    }

    // Do some basic logging for debug
    debug("Search String: %s\n", searchstring);
    debug("BPF Expression: %s\n", expression);

    // Set up to capture
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask = 0;   /* The netmask of our sniffing device */
    bpf_u_int32 net = 0;    /* The IP of our sniffing device */
    struct bpf_program filter;
    // Zero out the struct
    memset(&filter, 0, sizeof(struct bpf_program));

    // Figure out to read the file or read the interface
    if (inputfile == NULL) {
        if (interface == NULL) {
            // No interface provided; just pick one
            if ((interface = pcap_lookupdev(errbuf)) == NULL) {
                error("%s\n", errbuf);
                return EXIT_FAILURE;
            } else {
                info("Bounded to the default interface %s\n", interface);
            }
        } else {
            // User provided an interface, see if it exists
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
    } else {
        // User gave us an input file. Try to open it.
        if ((handle = pcap_open_offline(inputfile, errbuf)) == NULL) {
            error("Unable to read the offline dump %s: %s\n", inputfile, errbuf);
            return EXIT_FAILURE;
        }
    }

    // If theres a filter, make compile the filter and apply it
    if (expression != NULL) {
        // Compile the filter
        if (pcap_compile(handle, &filter, expression, 0, net) == -1) {
            error("Couldn't parse the filter %s: %s\n", expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        // Apply the filter
        if (pcap_setfilter(handle, &filter) == -1) {
            error("Couldn't apply the filter %s: %s\n", expression, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
    }

    // Start sniffing
    sniffinterface(handle, searchstring);

    // Close the session
    printf("\n");
    if (inputfile != NULL) {
        info("Ending parsing of input file %s...\n", inputfile);
    } else {
        info("Ending listening session on %s...\n", interface);
    }
    pcap_close(handle);

    return EXIT_SUCCESS;
}

static void sniffinterface(pcap_t *handle, char *searchstring) {
    if (handle == NULL)
        return;
    // We got this far, set up the signal handler
    signal(SIGINT, exithandler);

    // Now start reading the handle
    pcap_loop(handle, -1, callback, (u_char*)searchstring);
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
    if (args != NULL) {
        if (!searchpacket(packet, pkthdr->len, (char*)args)) {
            // Didn't find the search string, exit
            return;
        }
    }
    // source and destination IP
    // address and port, protocol (TCP, UDP, ICMP, OTHER), and the raw content of the
    // application-layer packet payload
    // Extract the time stamp
    char buffer[256];
    time_t ts = pkthdr->ts.tv_sec;
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S%P", localtime(&ts));
    printf("%s ", buffer);
    // Check to see if we have a ipv4 packet
    struct ethhdr *ehdr = (struct ethhdr *)packet;
    if (ntohs(ehdr->h_proto) == IPV4) {
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
        // Figure out protocol sensitive information
        switch (iph->protocol) {
            case TYPE_ICMP:
                printicmp(packet, pkthdr->caplen);
                break;
            case TYPE_UDP:
                printudp(packet, pkthdr->caplen);
                break;
            case TYPE_TCP:
                printtcp(packet, pkthdr->caplen);
                break;
            default:
                printother(packet, pkthdr->caplen);
                break;
        }
    } else {
        // We have something else like arp, etc.
        printeth(packet, pkthdr->caplen);
        // Print a OTHER and a newline
        printf("OTHER\n");
        // Print whatever is left
        printpayload(packet + sizeof(struct ethhdr), pkthdr->caplen - sizeof(struct ethhdr));
    }
    // Make a gap for the next packet
    printf("\n");
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
    printf("> %02x:%02x:%02x:%02x:%02x:%02x ",
        hdr->h_dest[0],
        hdr->h_dest[1],
        hdr->h_dest[2],
        hdr->h_dest[3],
        hdr->h_dest[4],
        hdr->h_dest[5]);
    // Print out the ethernet type
    printf("0x%04x ", ntohs(hdr->h_proto));
    // Print out the packet length
    printf("%5zu", length);
    // Print out a newline to force rest of output on next line
    printf("\n");
}

static size_t printip(const u_char *packet, size_t length, char *srcip, char *destip) {
    /*
    IP Layers
    +----------+
    | Ethernet |
    +----------+
    | IP       |
    +----------+
    */
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
    // IHL is the number of 32-bit words which make up the header
    // num words * (bytes / word) = total number of bytes
    return iph->ihl * 4;
}

static void printudp(const u_char* packet, size_t length) {
    char src[32], dst[32];
    size_t iphdrlen, payloadlen;
    printeth(packet, length);
    iphdrlen = printip(packet, length, src, dst);
    // Now do Specific udp stuff
    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + sizeof(struct ethhdr));
    printf("%s:%u > %s:%u UDP\n", src, udph->source, dst, udph->dest);
    // Now dump the payload
    /*
    UDP Layers
    +----------+
    | Ethernet |
    +----------+
    | IP       |
    +----------+
    | UDP      |
    +----------+
    | payload  |
    +----------+
    */
    payloadlen = length - sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
    if (payloadlen > 0) {
        printpayload(packet + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr), payloadlen);
    }
}

static void printtcp(const u_char* packet, size_t length) {
    char src[32], dst[32];
    size_t iphdrlen, hdrlen, payloadlen;
    // Print out eth and ip headers
    printeth(packet, length);
    iphdrlen = printip(packet, length, src, dst);
    // Get port information from tcp packet
    struct tcphdr *tcph = (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
    // Now do Specific tcp stuff
    printf("%s:%u > %s:%u TCP\n", src, tcph->source, dst, tcph->dest);
    // Calculate the size of the full heade to reach the payload
    hdrlen = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
    // Now dump the payload
    payloadlen = length - hdrlen;
    if (payloadlen > 0) {
        printpayload(packet + hdrlen, payloadlen);
    }
}

static void printicmp(const u_char* packet, size_t length) {
    char src[32], dst[32];
    size_t iphdrlen, payloadlen;
    printeth(packet, length);
    // Print the ip layer, and get its size
    iphdrlen = printip(packet, length, src, dst);
    // Now do Specific ICMP stuff
    printf("%s > %s ICMP\n", src, dst);
    // Calculate the size of the full header
    payloadlen = length - (sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr));
    debug("ICMP Payload: %zu\n", payloadlen);
    if (payloadlen > 0) {
        printpayload(packet + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr), payloadlen);
    }
}

static void printother(const u_char* packet, size_t length) {
    char src[32], dst[32];
    size_t iphdrlen, payloadlen;
    printeth(packet, length);
    iphdrlen = printip(packet, length, src, dst);
    // Now do Specific other stuff
    printf("%s > %s OTHER\n", src, dst);
    // Now just print out the raw payload contents
    payloadlen = length - sizeof(struct ethhdr) + iphdrlen;
    if (payloadlen > 0) {
        printpayload(packet + sizeof(struct ethhdr) + iphdrlen, payloadlen);
    }
}

static void printpayloadrow(unsigned char *buffer, size_t count) {
    int i;
    // Print the packets we have
    for (i = 0; i < count; ++i) {
        printf("%02x ", buffer[i]);
    }
    // If there is any other packets which don't exist print spaces
    for (; i < 16; ++i) {
        printf("   ");
    }
    // Print some space
    printf("  ");
    // Now print out the ascii value if possible
    for (i = 0; i < count; ++i) {
        char c = buffer[i];
        if (c < ' ' || c > '~') {
            c = '.';
        }
        printf("%c", c);
    }
    // Finally print a new line
    printf("\n");
}

static void printpayload(const u_char* packet, size_t length) {
    int i;
    size_t count;
    unsigned char buffer[16];
    memset(buffer, 0, 16);
    for (i = 0, count = 0; i < length; ++i, ++count) {
        if (count == 16) {
            printpayloadrow(buffer, count);
            // Reset the counter
            count = 0;
            // Zero out the buffer
            memset(buffer, 0, 16);
        }
        buffer[count] = packet[i];
    }
    // If there was anything left over, print it out
    if (count > 0)
        printpayloadrow(buffer, count);
}

static bool searchpacket(const u_char *packet, size_t length, char *search) {
    bool found = false;
    size_t payloadlen;
    struct ethhdr *ehdr = (struct ethhdr*) packet;
    size_t hdrlen = sizeof(struct ethhdr);

    // Check to see if we have an ipv4 packet
    if (ntohs(ehdr->h_proto) == IPV4) {
        struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
        hdrlen += (iph->ihl * 4);
        // Look to see if we have one of the 3 types we support
        struct tcphdr *tcphdr = NULL;
        // Figure out protocol sensitive information
        switch (iph->protocol) {
            case TYPE_ICMP:
                hdrlen += sizeof(struct icmphdr);
                break;
            case TYPE_UDP:
                /* Nothing else needs to be added to the length */
                hdrlen += sizeof(struct udphdr);
                break;
            case TYPE_TCP:
                tcphdr = (struct tcphdr*)(packet + hdrlen);
                hdrlen += (tcphdr->doff * 4);
                break;
            default:
                /* Just start scanning bytes from here */
                break;
        }
    }

    // Calculate the size of the payload
    payloadlen = length - hdrlen;
    // Check to make sure theres anything left in the packet, otherwise it may be empty
    if (payloadlen == 0) {
        // debug("No payload to scan, skipping\n");
        return found;
    }

    // Finally search for the payload string
    // 1500 is MTU for ETH, and 1 to null terminate
    unsigned char buffer[payloadlen + 2];
    memcpy(buffer, packet + hdrlen, payloadlen);
    // NULL terminate the buffer
    buffer[payloadlen + 1] = 0;
    if (strstr((char*)buffer, search) != NULL) {
        found = true;
    }
    return found;
}

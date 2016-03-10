#ifndef MYDUMP_H
#define MYDUMP_H
#include <stdio.h>

#define IPV4 0x0800
#define TYPE_ICMP 1
#define TYPE_TCP 6
#define TYPE_UDP 17

#define USAGE(name, stream, exit_code) do {                                    \
    fprintf((stream),                                                          \
    "%s [-h] [-i interface] [-r file] [-s string] [expression]"                \
    "\n\nFor each packet, mydump outputs a record containing \n"               \
    "the timestamp, source and destination MAC address, EtherType, packet \n"  \
    "length, source and destination IP address and port, protocol (TCP, UDP,\n"\
    "ICMP, OTHER), and the raw content of the application-layer packet \n"     \
    "payload."                                                                 \
    "\n\n"                                                                     \
    "-h                               Displays this help menu."                \
    "\n\n"                                                                     \
    "-i                               Listen on network device <interface>\n"  \
    "                                 (e.g., eth0). If not specified,\n"       \
    "                                 defaults to the first interface found."  \
    "\n\n"                                                                     \
    "-r                               Read packets from <file> (tcpdump format)." \
    "\n\n"                                                                     \
    "-s                               Keep only packets that contain\n"        \
    "                                 <string> in their payload."              \
    "\n\n"                                                                     \
    "expression                       A BPF filter that specifies which\n"     \
    "                                 packets will be dumped. If no filter is\n"\
    "                                 given, all packets seen on the interface\n"\
    "                                 (or contained in the trace) will be\n"   \
    "                                 dumped. Otherwise, only packets matching\n"\
    "                                 <expression> will be dumped.\n"          \
    , (name));                                                                 \
    exit((exit_code));                                                         \
} while(0)

#define CHECK_FLAG(value, flag)     \
({                                  \
    ((value) & flag) == (flag);     \
})

#endif

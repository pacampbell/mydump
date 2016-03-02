#ifndef MYDUMP_H
#define MYDUMP_H
#include <stdio.h>

#define TYPE_ICMP 1
#define TYPE_TCP 6
#define TYPE_UDP 17

#define USAGE(name, stream, exit_code) do {                                    \
    fprintf((stream),                                                          \
    "%s [-i interface] [-r file] [-s string] expression"                       \
    "\n%s [-i interface] [-r file] [-s string]"                                \
    "\n\nFor each packet, mydump outputs a record containing \n"               \
    "the timestamp, source and destination MAC address, EtherType, packet \n"  \
    "length, source and destination IP address and port, protocol (TCP, UDP,\n"\
    "ICMP, OTHER), and the raw content of the application-layer packet \n"     \
    "payload."                                                                 \
    "\n\n"                                                                     \
    "-i Listen on network device <interface> (e.g., eth0). If not \n"          \
    "specified, defaults to the first interface found."                        \
    "\n"                                                                       \
    "\n-r Read packets from <file> (tcpdump format)."                          \
    "\n"                                                                       \
    "\n-s Keep only packets that contain <string> in their payload."           \
    "\n"                                                                       \
    "\nexpression is a BPF filter that specifies which packets will be \n"     \
    "dumped. If no filter is given, all packets seen on the interface (or \n"  \
    "contained in the trace) will be dumped. Otherwise, only packets \n"       \
    "matching <expression> will be dumped.\n"                                  \
    , (name), (name));                                                         \
    exit((exit_code));                                                         \
} while(0)

#define CHECK_FLAG(value, flag)     \
({                                  \
    ((value) & flag) == (flag);     \
})

#endif

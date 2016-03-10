# CSE508 HW&#35;2 mydump

Passive network monitoring tool similar to tcpdump. It uses libpcap to
listen and sniff on a given interface. If no interface is provided, it will
attempt to bind to the first available interface. It currently only gives detailed
information for TCP, UDP, and ICMP packets. Any other packet type will have the
information which can be correctly extracted printed and then the rest of the
packet is printed in visible ASCII if possible. If there is no visible ASCII value
then a `.` is printed in its place.

# Author

Paul Campbell <paul.campbell@stonybrook.edu>

# Usage

<pre>
./mydump [-h] [-i interface] [-r file] [-s string] [expression]

For each packet, mydump outputs a record containing
the timestamp, source and destination MAC address, EtherType, packet
length, source and destination IP address and port, protocol (TCP, UDP,
ICMP, OTHER), and the raw content of the application-layer packet
payload.

-h                               Displays this help menu.

-i                               Listen on network device &lt;interface&gt;
                                 (e.g., eth0). If not specified,
                                 defaults to the first interface found.

-r                               Read packets from &lt;file&gt; (tcpdump format).

-s                               Keep only packets that contain
                                 &lt;string&gt; in their payload.

expression                       A BPF filter that specifies which
                                 packets will be dumped. If no filter is
                                 given, all packets seen on the interface
                                 (or contained in the trace) will be
                                 dumped. Otherwise, only packets matching
                                 &lt;expression&gt; will be dumped.
</pre>

# Dependencies

1. Make
    * Tested on **GNU Make 4.0**
2. gcc
    * Tested on **gcc (Ubuntu 5.2.1-22ubuntu2) 5.2.1 20151010**
3. libpcap
    * On a Debian based install `sudo apt-get install libpcap0.8-dev`

# Build

Typing `make help` will list all targets the **Makefile** can build.
To build all binaries in the **Makefile** type `make`.

# Note

If you are using a shell that is unable to render ANSI colors, edit the **Makefile**
so that the **CFLAGS** variable no longer defined **-DCOLOR**.

# Sample output of program

<pre>
2016-03-10 08:50:01am c4:85:08:45:b6:22 > d0:7e:28:c9:96:bf 0x0800    66
10.1.197.239:44192 > 204.236.230.155:47873 TCP

2016-03-10 08:50:04am c4:85:08:45:b6:22 > ff:ff:ff:ff:ff:ff 0x0800   237
10.1.197.239:23620 > 10.1.199.255:23620 UDP
7b 22 68 6f 73 74 5f 69 6e 74 22 3a 20 31 33 32   {"host_int": 132
33 33 39 36 35 31 39 37 30 38 36 34 35 39 31 31   3396519708645911
35 34 36 31 39 36 38 30 36 39 31 31 31 35 31 30   5461968069111510
35 35 32 37 2c 20 22 76 65 72 73 69 6f 6e 22 3a   5527, "version":
20 5b 32 2c 20 30 5d 2c 20 22 64 69 73 70 6c 61    [2, 0], "displa
79 6e 61 6d 65 22 3a 20 22 22 2c 20 22 70 6f 72   yname": "", "por
74 22 3a 20 31 37 35 30 30 2c 20 22 6e 61 6d 65   t": 17500, "name
73 70 61 63 65 73 22 3a 20 5b 38 35 32 31 38 37   spaces": [852187
37 37 36 2c 20 33 33 35 37 30 30 33 34 2c 20 32   776, 33570034, 2
36 37 37 35 31 34 37 2c 20 39 38 37 36 37 37 38   6775147, 9876778
39 2c 20 31 32 39 35 32 34 37 35 34 2c 20 32 39   9, 129524754, 29
31 35 31 38 35 39 2c 20 31 39 39 37 37 36 32 34   151859, 19977624
39 5d 7d 00 00 00 00 00 00 00 00 00 00 00 00 00   9]}.............
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
00 00 00 00 00 00 00 00 00 00 00                  ...........

2016-03-10 08:50:02am c4:85:08:45:b6:22 > d0:7e:28:c9:96:bf 0x0806    42
OTHER
00 01 08 00 06 04 00 01 c4 85 08 45 b6 22 0a 01   ...........E."..
c5 ef 00 00 00 00 00 00 0a 01 c0 01               ............

2016-03-10 08:55:36am c4:85:08:45:b6:22 > d0:7e:28:c9:96:bf 0x0800   476
10.1.197.239:65162 > 54.240.190.213:20480 TCP
47 45 54 20 2f 69 6d 61 67 65 73 2f 47 2f 30 31   GET /images/G/01
2f 62 72 6f 77 73 65 72 2d 73 63 72 69 70 74 73   /browser-scripts
2f 64 70 50 72 6f 64 75 63 74 49 6d 61 67 65 2f   /dpProductImage/
64 70 50 72 6f 64 75 63 74 49 6d 61 67 65 2d 32   dpProductImage-2
39 30 30 36 34 36 33 31 30 2e 5f 56 31 5f 2e 6a   900646310._V1_.j
73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74   s HTTP/1.1..Host
3a 20 7a 2d 65 63 78 2e 69 6d 61 67 65 73 2d 61   : z-ecx.images-a
6d 61 7a 6f 6e 2e 63 6f 6d 0d 0a 43 6f 6e 6e 65   mazon.com..Conne
63 74 69 6f 6e 3a 20 6b 65 65 70 2d 61 6c 69 76   ction: keep-aliv
65 0d 0a 41 63 63 65 70 74 3a 20 69 6d 61 67 65   e..Accept: image
2f 77 65 62 70 2c 69 6d 61 67 65 2f 2a 2c 2a 2f   /webp,image/*,*/
2a 3b 71 3d 30 2e 38 0d 0a 55 73 65 72 2d 41 67   *;q=0.8..User-Ag
65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30   ent: Mozilla/5.0
20 28 58 31 31 3b 20 4c 69 6e 75 78 20 78 38 36    (X11; Linux x86
5f 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74   _64) AppleWebKit
2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20   /537.36 (KHTML,
6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f   like Gecko) Chro
6d 65 2f 34 38 2e 30 2e 32 35 36 34 2e 31 31 36   me/48.0.2564.116
20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 0d 0a    Safari/537.36..
52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f   Referer: http://
77 77 77 2e 61 6d 61 7a 6f 6e 2e 63 6f 6d 2f 0d   www.amazon.com/.
0a 41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67   .Accept-Encoding
3a 20 67 7a 69 70 2c 20 64 65 66 6c 61 74 65 2c   : gzip, deflate,
20 73 64 63 68 0d 0a 41 63 63 65 70 74 2d 4c 61    sdch..Accept-La
6e 67 75 61 67 65 3a 20 65 6e 2d 55 53 2c 65 6e   nguage: en-US,en
3b 71 3d 30 2e 38 0d 0a 0d 0a                     ;q=0.8....

2016-03-10 09:37:48am d0:7e:28:c9:96:bf > c4:85:08:45:b6:22 0x0800    98
173.194.68.113 > 10.1.197.239 ICMP
bc 86 e1 56 00 00 00 00 ca 4c 0e 00 00 00 00 00   ...V.....L......
10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f   ................
20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f    !"#$%&'()*+,-./
30 31 32 33 34 35 36 37                           01234567
</pre>

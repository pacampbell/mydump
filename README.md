# CSE508 HW&#35;2 mydump

Passive network monitoring tool similar to tcpdump.

# Usage

<pre>
mydump [-i interface] [-r file] [-s string] expression
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

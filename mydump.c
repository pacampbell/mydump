#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mydump.h"
#include "debug.h"


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
    }

    // Make sure the interface exists

    // Do some basic logging for debug
    debug("Search String: %s\n", searchstring);
    debug("Expression: %s\n", expression);

    return EXIT_SUCCESS;
}

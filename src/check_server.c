/* CHECK SERVER.c
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:42:18
 * Last edited:
 *   11/09/2020, 16:53:46
 * Auto updated?
 *   Yes
 *
 * Description:
 *   This file contains a simple test to see if the given server is
 *   responding to TCP connections. It makes use of the test_server_status
 *   function, in the similarly named C-file.
 * 
 *   For a list of the most important sources used, please refer to the header
 *   in exploit.c.
**/


#include <stdio.h>
#include <stddef.h>

#include "tools.h"
#include "test_server_status.h"
#include "globals.h"


/***** HELPER FUNCTIONS *****/
/* Prints a neat help message. */
void print_help(char* executable) {
    printf("Usage: %s -h -s SERVER_IP -i INTERFACE\n", executable);
    printf("\n-h, --help\t\tShows this help message.\n");
    printf("\n-s, --server\t\tSets the server IPv4-address that we want to check (DEFAULT: %u.%u.%u.%u).\n",
           IP_FORMAT(DEFAULT_SERVER_ADDR));
    printf("\n-i, --interface\t\tSets the interface we want to use (DEFAULT: %s).\n",
           DEFAULT_INTERFACE);
    printf("\n");
}

/* Parses the commandline arguments. Returns 0 on success, or an error code if something went wrong. */
int parse_cli(uint32_t* server_ip, char* interface, int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            // Either single-label or multi-label
            if ((arg[1] == 'h' && arg[2] == '\0') || streq(arg + 1, "-help")) {
                // Print the help message, then quit
                print_help(argv[0]);
                return -2;
            } else if ((arg[1] == 's' && arg[2] == '\0') || streq(arg + 1, "-server")) {
                // xterm ip, so parse the next argument as an ip
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_ip(server_ip, argv[i + 1])) { return EXIT_FAILURE; }
            } else if ((arg[1] == 'i' && arg[2] == '\0') || streq(arg + 1, "-interface")) {
                // xterm ip, so parse the next argument as an ip
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (strlen(argv[i + 1]) >= MAX_INTERFACE_SIZE) {
                    fprintf(stderr, "[ERROR] Too long name for interface '%s'.\n", argv[i + 1]);
                    return -1;
                }
                strcpy(interface, argv[i + 1]);
            } else {
                fprintf(stderr, "[ERROR] Unknown option '%s' (see '--help' for a complete list).\n", arg);
                return -1;
            }
        }
    }

    // Done
    return 0;
}



/***** ENTRY POINT *****/
int main(int argc, char** argv) {
    // First, parse the CLI args
    uint32_t server_ip = DEFAULT_SERVER_ADDR;
    char interface[MAX_INTERFACE_SIZE];
    strcpy(interface, DEFAULT_INTERFACE);
    int result = parse_cli(&server_ip, interface, argc, argv);
    if (result != 0) {
        return result;
    }



    /* Print a neat header message. */
    printf("\n*** SERVER STATUS CHECK ***\n\n");

    // Print the options used
    printf("Using options:\n");
    printf(" - Server IP : %u.%u.%u.%u\n", IP_FORMAT(server_ip));
    printf(" - Interface : '%s'\n", interface);
    printf("\n");
    fflush(stdout);



    /* Open the libnet raw socket. */
    printf("Initializing libnet on interface '%s'...\n", interface);
    // Initialize the the error message buffer. Note that we will also use this for PCAP, so we use whatever constant is longer
    char errbuf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ? LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE];

    // Open a raw IP4 socket
    libnet_t* l;
    l = libnet_init(LIBNET_RAW4, interface, errbuf);
    if (l == NULL) {
        fprintf(stderr, "[ERROR] Could not initialize libnet: %s\n\n", errbuf);
        return EXIT_FAILURE;
    }

    // Set the random seed appropriately
    if (libnet_seed_prand(l) == -1) {
        libnet_destroy(l);
        fprintf(stderr, "[ERROR] Could not seed the random number generator of libnet.\n");
        return EXIT_FAILURE;
    }



    /* Then, open the pcap socket. */
    printf("Initializing pcap on interface '%s'...\n", interface);
    // Create the pcap handle to listen for packets
    pcap_t* p = pcap_open_live(interface, BUFSIZ, 1, DOS_VERIFY_TIMEOUT, errbuf);
    if (p == NULL) {
        libnet_destroy(l);
        fprintf(stderr, "[ERROR] Failed to open device '%s' for packet capture: %s\n", interface, errbuf);
        return -1;
    }

    // Then, run the test_server_status function and see if it works
    printf("Checking server status...\n");
    result = test_server_status(l, p, errbuf, interface, server_ip, DEFAULT_SERVER_PORT);
    if (result == 1) {
        printf("\nServer appears to be OFFLINE (succesfully DoS'd)\n");
    } else if (result == 0) {
        printf("\nServer appears to be ONLINE (not DoS'd)\n");
    } else {
        libnet_destroy(l);
        return result;
    }

    // Done, close the sockets
    libnet_destroy(l);

    // We did!
    printf("\nDone.\n\n");
    return EXIT_SUCCESS;
}

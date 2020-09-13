/* XTERM PROBE.c
 *   by Lut99
 *
 * Created:
 *   13/09/2020, 15:13:48
 * Last edited:
 *   13/09/2020, 15:38:10
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Sends a given number of empty TCP-SYN packets to the xterm to allow
 *   something such as tcpdump to display xterm responses, which let us
 *   analyse its sequence number generation algorithm.
**/

typedef unsigned int uint;
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <libnet.h>
#include <pcap.h>

#include "globals.h"
#include "tools.h"
#include "networking.h"


/***** CONSTANTS *****/
/* The number of packets to send. */
#define DEFAULT_N_PACKETS 10



/***** HELPER FUNCTIONS *****/
/* Prints a neat help message. */
void print_help(char* executable) {
    printf("Usage: %s -x XTERM_IP -s SERVER_IP -i INTERFACE\n", executable);
    printf("\n-h, --help\t\tShows this help message.\n");
    printf("\n-i, --xterm-ip\t\tSets the xterminal IPv4-address that we want to use for the probing (DEFAULT: %u.%u.%u.%u).\n",
           IP_FORMAT(DEFAULT_XTERM_ADDR));
    printf("\n-p, --xterm-port\tSets the xterminal port that we want to probe on (DEFAULT: random\n)");
    printf("\n-P, --source-port\tSets the source port that we want to receive replies on (DEFAULT: random\n)");
    printf("\n-d, --device\t\tSets the interface we want to use (DEFAULT: %s).\n",
           DEFAULT_INTERFACE);
    printf("\n-n, --number\t\tSets the number of probe packets to send in one go (DEFAULT: %u).\n",
           DEFAULT_N_PACKETS);
    printf("\n");
}

/* Parses the commandline arguments. Returns 0 on success, or an error code if something went wrong. */
int parse_cli(uint32_t* xterm_ip, uint16_t* xterm_port, uint16_t* source_port, char* interface, uint16_t* n, int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        char* arg = argv[i];
        if (arg[0] == '-') {
            // Either single-label or multi-label
            if ((arg[1] == 'h' && arg[2] == '\0') || streq(arg + 1, "-help")) {
                // Print the help message, then quit
                print_help(argv[0]);
                return -2;
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
            } else if ((arg[1] == 'P' && arg[2] == '\0') || streq(arg + 1, "-source-port")) {
                // spoofed port, so parse the next argument as an 16-bit unsigned integer
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_uint16(source_port, argv[i + 1])) {
                    fprintf(stderr, "[ERROR] Could not parse '%s' as a 16-bit port number.\n", argv[i + 1]);
                    return EXIT_FAILURE;
                }
            } else if ((arg[1] == 'd' && arg[2] == '\0') || streq(arg + 1, "-device")) {
                // xterm ip, so parse the next argument as an ip
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (strlen(argv[i + 1]) >= MAX_INTERFACE_SIZE) {
                    fprintf(stderr, "[ERROR] Device name '%s' too long.\n", argv[i + 1]);
                    return -1;
                }
                strcpy(interface, argv[i + 1]);
            } else if ((arg[1] == 'n' && arg[2] == '\0') || streq(arg + 1, "-number")) {
                // xterm ip, so parse the next argument as an ip
                if (i == argc - 1) {
                    fprintf(stderr, "[ERROR] Missing value for '%s'.\n", arg);
                    return -1;
                }
                if (!str_to_uint16(n, argv[i + 1])) {
                    fprintf(stderr, "[ERROR] Could not parse '%s' as the 16-bit number of packets to send.\n", argv[i + 1]);
                    return EXIT_FAILURE;
                }
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
    /* Parse the command line args. */
    // Declare the space to hold the values
    uint32_t xterm_ip = DEFAULT_XTERM_ADDR;
    uint16_t xterm_port = libnet_get_prand(LIBNET_PRu16);
    uint16_t source_port = libnet_get_prand(LIBNET_PRu16);
    char interface[MAX_INTERFACE_SIZE];
    strcpy(interface, DEFAULT_INTERFACE);
    uint16_t n = DEFAULT_N_PACKETS;

    // Parse the CLI
    int result = parse_cli(&xterm_ip, &xterm_port, &source_port, interface, &n, argc, argv);
    if (result == -2) { return EXIT_SUCCESS; }
    else if (result != 0) { return result; }

    // Acquire our own IPv4-address & mask
    char errbuf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ? LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE];
    bpf_u_int32 source_ip, source_netmask;
    if (pcap_lookupnet(interface, &source_ip, &source_netmask, errbuf) == -1) {
        fprintf(stderr, "\n[ERROR] Failed to obtain address & netmask of interface '%s'\n", errbuf);
        return -1;
    }



    /* Print a neat header message. */
    printf("\n*** XTERM SYN PROBE ***\n\n");

    // Print the options used
    printf("Using options:\n");
    printf(" - Source IP      : %u.%u.%u.%u\n", IP_FORMAT(source_ip));
    printf(" - Source port    : %u\n", source_port);
    printf(" - Xterminal IP   : %u.%u.%u.%u\n", IP_FORMAT(xterm_ip));
    printf(" - Xterminal port : %u\n", xterm_port);
    printf(" - Interface      : '%s'\n", interface);
    printf(" - No. packets    : '%u'\n", n);
    printf("\n");
    fflush(stdout);



    /* Initialize libnet. */
    printf("Initializing libnet on interface '%s'...\n", interface);
    libnet_t* l = libnet_init(LIBNET_RAW4, interface, errbuf);
    if (l == NULL) {
        fprintf(stderr, "[ERROR] Could not initialize libnet: %s\n\n", errbuf);
        return EXIT_FAILURE;
    }

    

    /* Send the packets. */
    printf("Sending probe packets to %u.%u.%u.%u...\n", IP_FORMAT(xterm_ip));

    // First, create the TCP-SYN packet we'll send
    result = create_tcp_syn(
        l,
        source_ip, source_port,
        xterm_ip, xterm_port,
        0, 0,
        NULL, 0
    );
    if (result != 0) {
        return result;
    }

    // Next, send it the specified number of time
    for (int i = 1; i <= n; i++) {
        if (libnet_write(l) == -1) {
            fprintf(stderr, "[ERROR] Could not send probe packet %d/%d: %s\n", i, n, libnet_geterror(l));
            return EXIT_FAILURE;
        }
    }
    printf("Done (check 'tcpdump' for any replies)\n");

    // Cleanup
    libnet_destroy(l);

    // Done!
    printf("\nDone.\n\n");
    return EXIT_SUCCESS;
}

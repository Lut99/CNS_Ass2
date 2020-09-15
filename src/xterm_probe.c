/* XTERM PROBE.c
 *   by Lut99
 *
 * Created:
 *   13/09/2020, 15:13:48
 * Last edited:
 *   15/09/2020, 16:50:43
 * Auto updated?
 *   Yes
 *
 * Description:
 *   Sends a given number of empty TCP-SYN packets to the xterm and receives
 *   the xterm's replies, after which is neatly terminates the connection using
 *   TCP-RST. Additionally, once all packets are received, it prints the ack's
 *   received and performs a very simpel analysis showing their relative
 *   change.
**/

typedef unsigned int uint;
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <libnet.h>
#include <pcap.h>
#include <sys/time.h>

#include "globals.h"
#include "tools.h"
#include "networking.h"


/***** CONSTANTS *****/
/* The default number of probes to perform. */
#define DEFAULT_N_PROBES 50



/***** HELPER FUNCTIONS *****/
/* Prints a neat help message. */
void print_help(char* executable) {
    printf("Usage: %s -x XTERM_IP -s SERVER_IP -i INTERFACE\n", executable);
    printf("\n-h, --help\t\tShows this help message.\n");
    printf("\n-i, --xterm-ip\t\tSets the xterminal IPv4-address that we want to use for the probing (DEFAULT: %u.%u.%u.%u).\n",
           IP_FORMAT(DEFAULT_XTERM_ADDR));
    printf("\n-p, --xterm-port\tSets the xterminal port that we want to probe on (DEFAULT: %u\n)",
           DEFAULT_RSH_PORT);
    printf("\n-P, --source-port\tSets the source port that we want to receive replies on. Set to 0 to choose a random port (DEFAULT: 0\n)");
    printf("\n-d, --device\t\tSets the interface we want to use (DEFAULT: %s).\n",
           DEFAULT_INTERFACE);
    printf("\n-n, --number\t\tSets the number of probes to send consecutively (DEFAULT: %u).\n",
           DEFAULT_N_PROBES);
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
                    fprintf(stderr, "[ERROR] Could not parse '%s' as the 16-bit number of probes to send.\n", argv[i + 1]);
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
    uint16_t xterm_port = DEFAULT_RSH_PORT;
    uint16_t source_port = 0;
    char interface[MAX_INTERFACE_SIZE];
    strcpy(interface, DEFAULT_INTERFACE);
    uint16_t n = DEFAULT_N_PROBES;

    // Parse the CLI
    int result = parse_cli(&xterm_ip, &xterm_port, &source_port, interface, &n, argc, argv);
    if (result == -2) { return EXIT_SUCCESS; }
    else if (result != 0) { return result; }
    


    /* Print a neat header message. */
    printf("\n*** XTERM SEQ PROBE ***\n\n");

    
    
    /* Initialize libnet. */
    printf("Initializing libnet on interface '%s'...\n", interface);

    // Initialize the error buffer (which is shared between libnet and pcap, so take the one with the larger buffer size)
    char errbuf[LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ? LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    // Get the library context
    libnet_t* l = libnet_init(LIBNET_RAW4, interface, errbuf);
    if (l == NULL) {
        libnet_destroy(l);
        fprintf(stderr, "[ERROR] Could not initialize libnet: %s\n\n", errbuf);
        return EXIT_FAILURE;
    } else if (errbuf[0] != '\0') {
        // Passed but an error? => must be a warning, then
        fprintf(stderr, "[WARNING] %s\n", errbuf);
    }

    // Also seed libnet
    libnet_seed_prand(l);

    // And get the source IP & source port
    uint32_t source_ip = libnet_get_ipaddr4(l);
    if (source_port == 0) { source_port = libnet_get_prand(LIBNET_PRu16); }



    /* Initialize pcap. */
    printf("Initializing pcap on interface '%s'...\n", interface);
    pcap_t* p = pcap_open_live(interface, BUFSIZ, 1, PCAP_INTERVAL, errbuf);
    if (p == NULL) {
        libnet_destroy(l);
        fprintf(stderr, "[ERROR] Failed to open device '%s' for packet capture: %s\n", interface, errbuf);
        return -1;
    }



    /* Print the options used. */
    printf("\nUsing options:\n");
    printf(" - Source IP      : %u.%u.%u.%u\n", IP_FORMAT(source_ip));
    printf(" - Source port    : %u\n", source_port);
    printf(" - Xterminal IP   : %u.%u.%u.%u\n", IP_FORMAT(xterm_ip));
    printf(" - Xterminal port : %u\n", xterm_port);
    printf(" - Interface      : '%s'\n", interface);
    printf(" - No. probes     : %u\n", n);
    printf("\n");
    fflush(stdout);

    

    /* Begin probing. */
    uint32_t results[n];
    result = probe_tcp_seq(
        results,
        l, p,
        source_ip, source_port,
        xterm_ip, xterm_port,
        n
    );
    if (result != 0) {
        libnet_destroy(l);
        pcap_close(p);
        return result;
    }



    /* Print the result of the probe. */
    printf("\nResults:\n");
    uint32_t dseqs[n - 1];
    for (int i = 0; i < n; i++) {
        printf(" - Probe %03d: ACK %u\n", i + 1, results[i]);
        if (i < n - 1) {
            dseqs[i] = results[i + 1] - results[i];
            printf("      Difference with next     : %u\n", dseqs[i]);
            if (i > 0) {
                printf("      Difference in difference : %u\n", dseqs[i] - dseqs[i - 1]);
            }
        }
    }



    /* Cleanup. */
    libnet_destroy(l);
    pcap_close(p);



    // Done!
    printf("\nDone.\n\n");
    return EXIT_SUCCESS;
}

/* CHECK SERVER.c
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:42:18
 * Last edited:
 *   11/09/2020, 15:05:31
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
    printf("\n-s, --server\t\tSets the server IPv4-address that we want to check (DEFAULT: %d.%d.%d.%d).\n",
           IP_FORMAT(DEFAULT_SERVER_ADDR, 0));
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
    

    return EXIT_SUCCESS;
}

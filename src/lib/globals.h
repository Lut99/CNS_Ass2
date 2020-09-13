/* GLOBALS.h
 *   by Lut99
 *
 * Created:
 *   11/09/2020, 14:57:51
 * Last edited:
 *   13/09/2020, 15:36:17
 * Auto updated?
 *   Yes
 *
 * Description:
 *   A file containing global constants.
**/

#ifndef GLOBALS_H
#define GLOBALS_H


/***** MACROS *****/
/* Returns the correct 8-bits of an IP-address. */
#define IP_PART(ADDR, I) \
    (((ADDR) >> (8 * (3 - I))) & 0xFF)
/* Returns the IP-address as 4 8-bit parts, ready to be parsed by a xprintf function. */
#define IP_FORMAT(ADDR) \
    ((ADDR) & 0xFF), (((ADDR) >> 8) & 0xFF), (((ADDR) >> 16) & 0xFF), (((ADDR) >> 24) & 0xFF)



/***** CONSTANTS *****/
/* The maximum number of characters (including null-character) in an interface string. */
#define MAX_INTERFACE_SIZE 8
/* The default ip-address (as a 32-bit number) of the attacker. */
#define DEFAULT_SOURCE_ADDR 0x023610AC
/* The default ip-address (as a 32-bit number) of the xterminal. */
#define DEFAULT_XTERM_ADDR 0x043610AC
/* The default ip-address of the server. */
#define DEFAULT_SERVER_ADDR 0x033610AC
/* The default interface. */
#define DEFAULT_INTERFACE "eth0"
/* The default destination port used for DoS'ing the server. */
#define DEFAULT_SERVER_PORT 513
/* The maximum number of tries to DoS. */
#define MAX_DOS_TRIES 5
/* The timeout (in milliseconds) for the program to wait for the server's packets after the DoS-attack. */
#define DOS_VERIFY_TIMEOUT 1000
/* The default timeout for pcap sockets. */
#define PCAP_TIMEOUT 1000

#endif

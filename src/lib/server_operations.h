/* SERVER OPERATIONS.h
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:43:14
 * Last edited:
 *   11/09/2020, 20:59:47
 * Auto updated?
 *   Yes
 *
 * Description:
 *   The functions and files in this file check if the server at the given
 *   ip is reachable over the given interface. Doing so allows the user to,
 *   in effect, check if an TCP sync flood DoS-attack was succesfull.
 * 
 *   For a list of the most important sources used, please refer to the header
 *   in exploit.c.
**/

#ifndef SERVER_OPERATIONS_H
#define SERVER_OPERATIONS_H

typedef unsigned int uint;
#include <stdint.h>
#include <sys/types.h>
#include <libnet.h>
#include <pcap.h>


/* Tries to enable the given server with the given address on the given TCP-port by sending a SYN-packed with 'enabled' in the payload. Returns 0 if succesfull, or anything else if it wasn't. */
extern int server_enable(libnet_t* l, uint16_t source_ip, uint16_t source_port, uint32_t target_ip, uint16_t target_port);

/* Tries to disable the given server with the given address on the given TCP-port by performing a DoS-attack: we send ten TCP-SYN packets with 'disable' in their payload. Returns 0 if succesfull, or anything else if it wasn't. */
extern int server_disable(libnet_t* l, uint16_t source_ip, uint16_t source_port, uint32_t target_ip, uint16_t target_port);

/* Tests if the given server is reachable over the given interface on the given TCP-port via TCP. Returns 1 if it is, 0 if it isn't and -1 if an error occured, which is written to the given error buffer. */
extern int server_check_status(libnet_t* l, pcap_t* p, char* errbuf, char* interface, uint32_t target_ip, uint16_t target_port);

#endif

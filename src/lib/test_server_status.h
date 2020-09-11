/* TEST SERVER STATUS.h
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:43:14
 * Last edited:
 *   11/09/2020, 14:57:25
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

#ifndef TEST_SERVER_STATUS_H
#define TEST_SERVER_STATUS_H

typedef unsigned int uint;
#include <libnet.h>
#include <pcap.h>


/* The test_server_status function, which tests if the given server is reachable over the given interface on the given TCP-port via TCP. Returns 1 if it is, 0 if it isn't and -1 if an error occured, which is written to the given error buffer. */
int test_server_status(libnet_t* l, pcap_t* p, char* interface, uint32_t target_ip, uint16_t target_port);

#endif

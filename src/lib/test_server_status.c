/* TEST SERVER STATUS.c
 *   by Lut99
 *
 * Created:
 *   10/09/2020, 21:21:53
 * Last edited:
 *   10/09/2020, 21:26:10
 * Auto updated?
 *   Yes
 *
 * Description:
 *   The functions and files in this file check if the server at the given
 *   ip is reachable over the given interface. Doing so allows the user to,
 *   in effect, check if an TCP sync flood DoS-attack was succesfull.
**/

typedef unsigned int uint;
#include <libnet.h>
#include <pcap.h>


/* The test_server_status function, which tests if the given server is reachable over the given interface on the given TCP-port via TCP. Returns 1 if it is, 0 if it isn't and -1 if an error occured, which is written to the given error buffer. */
int test_server_status(libnet_t* l, pcap_t* p, char* interface, char* target_ip, uint16_t port) {
    // Build the TCP header
    uint32_t source_port = libnet_get_prand(LIBNET_PRu16);
    libnet_ptag_t tcp = libnet_build_tcp(
        source_port,                    // We use any arbitrary source port number
        port,
        libnet_get_prand(LIBNET_PRu16), // We use any arbitrary sequence number
        0,                              // We use any arbitrary acknowledgement number
        TH_SYN,                         // We use only the SYN control
        7,                              // The window size (pretty arbitrary as well)
        0,                              // The checksum will be handled automatically by libnet
        0,                              // The urgent pointer - zero, as it's not urgent
        LIBNET_TCP_H,                   // Total TCP packet length
        NULL,                           // No payload, as we're only interested in server response right now
        0,                              // Payload size of no payload is 0
        l,
        0                               // We want to build a new header rather than modify one
    );
    if (tcp == -1) {
        fprintf(stderr, "\n[ERROR] Could not build the DoS-verification TCP header: %s\n", libnet_geterror(l));
        return -1;
    }
    
    // Extract the ipv4 and netmask of this interface
    char pcap_error[PCAP_ERRBUF_SIZE];
    bpf_u_int32 attacker_ip, attacker_netmask;
    if (pcap_lookupnet(interface, &attacker_ip, &attacker_netmask, pcap_error) == -1) {
        fprintf("\n[ERROR] Failed to obtain netmask of interface '%s'\n", pcap_error);
        return -1;
    }

    // Next, we build the ipv4 header
    libnet_ptag_t ipv4 = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,                   // Total packet size
        0,                                              // Neutral Terms-of-Service
        libnet_get_prand(LIBNET_PRu16),                 // Arbitrary IP ID
        0,                                              // No fragment offset
        127,                                            // The time-to-live on the webs
        IPPROTO_TCP,                                    // The next protocol is our TCP
        0,                                              // Autofill the checksum
        attacker_ip,
        server_ip,
        NULL,                                           // No payload, as libpcap will link these together
        0,                                              // Payload size is therefore also NULL
        l,
        0                                               // We want to build a new header rather than modify one
    );
    if (ipv4 == -1) {
        fprintf(stderr, "\n[ERROR] Could not build the DoS-verification IPv4 header: %s\n", libnet_geterror(l));
        return -1;
    }

    // Create the pcap handle to listen for packets
    pcap_t* p = pcap_open_live(interface, BUFSIZ, 1, DOS_VERIFY_TIMEOUT, pcap_error);
    if (p == NULL) {
        fprintf("\n[ERROR] Failed to open device '%s' for packet capture: %s\n", interface, pcap_error);
        return -1;
    }

    // Compile the filter used for the interface
    char filter[1024];
    sprintf(filter, "(src host %d.%d.%d.%d) && (dst host %d.%d.%d.%d) && (src port %d) && (dst port %d) && (tcp[tcpflags] & (tcp-syn|tcp-ack))",
            IP_PART(server_ip, 0), IP_PART(server_ip, 1), IP_PART(server_ip, 2), IP_PART(server_ip, 3),
            IP_PART(attacker_ip, 0), IP_PART(attacker_ip, 1), IP_PART(attacker_ip, 2), IP_PART(attacker_ip, 3),
            DEFAULT_DOS_TARGET_PORT,
            port);
    struct bpf_program* filter_program;
    if (pcap_compile(p, bpf_program, filter, ))

    // Send the packet three times, to account for packets that might be lost
    for (int i = 1; i <= 3; i++) {
        if (libnet_write(l) == -1) {
            fprintf(stderr, "[ERROR] Could not send DoS-verification packet %d/3: %s\n", i, libnet_geterror(l));
            return EXIT_FAILURE;
        }

        // Wait for a response
        struct pcap_pkthdr* packet = pcap_next(p, packet);
        if (packet != NULL) {
            // We received a valid packet, which means that our DoS failed...
            pcap_close(p);
            return 0;
        }

        // We didn't receive a packet in time, so try again!   
    }

    // We did it!
    pcap_close(p);
    return 1;
}

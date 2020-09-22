/* TOOLS.c
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:48:33
 * Last edited:
 *   11/09/2020, 21:03:09
 * Auto updated?
 *   Yes
 *
 * Description:
 *   A file containing common tools and helper functions.
**/

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "tools.h"


/* Returns 1 if given two strings are equal, or 0 otherwise. */
int streq(char* s1, char* s2) {
    for (int i = 0; ; i++) {
        if (s1[i] != s2[i]) { return 0; }
        else if (s1[i] == '\0') { return 1; }
    }
}



/* Converts given string to a 32-bit ip-address. Returns 1 if it was successful, or 0 otherwise. */
int str_to_ip(uint32_t* result, char* ip_addr) {
    int ip[4];
    int offset;
    if (sscanf(ip_addr, "%u.%u.%u.%u %n", ip, ip + 1, ip + 2, ip + 3, &offset) < 4) { return 0; }
    
    // Check if not any other characters
    if (strlen(ip_addr) != (size_t) offset) { return 0; }

    // Try to convert each number
    *result = 0x0;
    for (int i = 0; i < 4; i++) {
        if (ip[i] > 255) { return 0; }
        (*result) |= ip[i] << (i * 8);
    }

    // Succes!
    return 1;
}

/* Converts given string to 16-bit number (for, for example, port numbers). Returns 1 if it was successful, or 0 otherwise. */
int str_to_uint16(uint16_t* result, char* port) {
    *result = 0;
    for (int i = 0; ; i++) {
        char c = port[i];

        // We're successfull if we made it all the way to the end of the string
        if (c == '\0') { return 1; }

        // Parse the rest of the characters
        if (c >= '0' && c <= '9') {
            // Read the value and check if an overflow would occur
            int value = (int) (c - '0');
            if (*result > UINT16_MAX / 10 - value) { return 0; }

            // Otherwise, simply add the value to the result
            *result = (*result) * 10 + value;
        } else { return 0; }
    }
}

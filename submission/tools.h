/* TOOLS.h
 *   by DukeD1rtfarm3r
 *
 * Created:
 *   11/09/2020, 14:48:51
 * Last edited:
 *   13/09/2020, 22:18:03
 * Auto updated?
 *   Yes
 *
 * Description:
 *   A file containing common tools and helper functions.
**/

#ifndef TOOLS_H
#define TOOLS_H

#include <stddef.h>
#include <stdint.h>


/* Returns 1 if given two strings are equal, or 0 otherwise. */
int streq(char* s1, char* s2);

/* Converts given string to a 32-bit ip-address. Returns 1 if it was successful, or 0 otherwise. */
int str_to_ip(uint32_t* result, char* ip_addr);
/* Converts given string to 16-bit number (for, for example, port numbers). Returns 1 if it was successful, or 0 otherwise. */
int str_to_uint16(uint16_t* result, char* port);

#endif

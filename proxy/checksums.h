/******************************************************************************
 * IPv4 and IPv6 Header Checksum Code
 *
 * Copyright (C) 2013  Samuel Jero <sj323707@ohio.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Samuel Jero <sj323707@ohio.edu>
 * Date: 02/2013
 * ******************************************************************************/
#ifndef CHECKUMS_H
#define CHECKSUMS_H

#include <ctype.h>
#include <sys/types.h>

#define IP4_ADDR_LEN 	4
#define IP6_ADDR_LEN 	16

u_int16_t ipv6_pseudohdr_chksum(u_char* buff, int len, u_char* dest, u_char* src, int type);
u_int16_t ipv4_pseudohdr_chksum(u_char* buff, int len, u_char* dest, u_char* src, int type);
u_int16_t ipv4_chksum(u_char* buff, int len);


#endif

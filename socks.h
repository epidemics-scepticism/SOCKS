/*
    Copyright (C) 2016 cacahuatl < cacahuatl at autistici dot org >

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#include <stdint.h>

/*
 *int s = tor_connect("google.com", "80",
 *			"127.0.0.1", "9050",
 *			"username", "password");
 *	returns -1 on failure, otherwise a socket fd
 */

int
tor_connect(const uint8_t *h, const uint8_t *p, /* destination hostname, destination port */
		const uint8_t *th, const uint8_t *tp, /* tor socks ip, tor socks port */
		const uint8_t *su, const uint8_t *sp); /* socks username, socks password */

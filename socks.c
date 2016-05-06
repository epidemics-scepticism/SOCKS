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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * RFC 1928, RFC 1929
 * SOCKS Protocol Version 5
 * Username/Password Authentication for SOCKS V5
 */

static bool
send_all(int s, const uint8_t *d, uint64_t ds)
{
	if (0 > s || !d) return false;
	for (uint64_t tot = 0; tot < ds;) {
		ssize_t tmp = send(s, &d[tot], ds - tot, 0);
		if (tmp < 0) return false;
		tot += tmp;
	}
	return true;
}

static bool
recv_all(int s, uint8_t *d, uint64_t ds)
{
	if (0 > s || !d) return false;
	for (uint64_t tot = 0; tot < ds;) {
		ssize_t tmp = recv(s, &d[tot], ds - tot, MSG_WAITALL);
		if (tmp < 0) return false;
		tot += tmp;
	}
	return true;
}

static bool
socks5_start(int s)
{
	uint8_t tx[3] = { 0x5, 0x1, 0x2 }, /* version, number of methods, method*/
		rx[2] = { 0 }; /* version, accepted method */
	if (false == send_all(s, tx, sizeof(tx))) return false;
	if (false == recv_all(s, rx, sizeof(rx))) return false;
	if (tx[0] != rx[0] || tx[2] != rx[1]) return false;
	return true;
}

static bool
socks5_auth(int s, const uint8_t *u, const uint8_t *p)
{
	if (0 > s || !u || !p) return false;
	uint64_t ul = strnlen((const char *)u, 256),
		 pl = strnlen((const char *)p, 256);
	if (256 == ul || 0 == ul || 256 == pl || 0 == pl) return false;
	if (false == send_all(s, (uint8_t *)"\x01", 1)) return false; /* auth method version */
	if (false == send_all(s, (uint8_t *)&ul, 1)) return false; /* username length */
	if (false == send_all(s, u, ul)) return false; /* username */
	if (false == send_all(s, (uint8_t *)&pl, 1)) return false; /* password length */
	if (false == send_all(s, p, pl)) return false; /* password */
	uint8_t rx[2] = { 0 }; /* auth method version, status */
	if (false == recv_all(s, rx, sizeof(rx))) return false;
	if (0x1 != rx[0] || 0x0 != rx[1]) return false;
	return true;
}

static bool
socks5_request(int s, const uint8_t *h, const uint8_t *ps)
{
	if (0 > s || !h || !ps) return false;
	uint64_t hl = strnlen((const char *)h, 256);
	if (256 == hl || 0 == hl) return false;
	uint16_t p = 0;
	sscanf((const char *)ps, "%hu", &p);
	p = htons(p);
	if (0 == p) return false;
	uint8_t tx[4] = { 0x5, 0x1, 0x0, 0x3 }; /* version, command, reserved, type */
	if (false == send_all(s, tx, 4)) return false;
	if (false == send_all(s, (uint8_t *)&hl, 1)) return false; /* hostname length */
	if (false == send_all(s, h, hl)) return false; /* hostname */
	if (false == send_all(s, (uint8_t *)&p, 2)) return false; /* port */
	uint8_t rx[256] = { 0 }; /* version, reply, reserved, type, address, port */
	if (false == recv_all(s, rx, 4)) return false;
	if (rx[0] != tx[0] || rx[1] || rx[2]) return false;
	switch (rx[3]) {
		case 0x1:
			if (false == recv_all(s, rx, 4)) return false;
			break;
		case 0x3:
			if (false == recv_all(s, rx, 1)) return false;
			if (false == recv_all(s, rx, rx[0])) return false;
			break;
		case 0x4:
			if (false == recv_all(s, rx, 16)) return false;
			break;
		default:
			return false;
	}
	return true;
}

static int
tor_socks_socket(const uint8_t *h, const uint8_t *ps)
{
	if (!h || !ps) return -1;
	uint16_t p = 0;
	sscanf((const char *)ps, "%hu", &p);
	struct sockaddr_in tor = {
		.sin_family = AF_INET,
		.sin_port = htons(p),
		.sin_addr.s_addr = inet_addr((const char *)h),
	};
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (0 > s) return -1;
	if (connect(s, (struct sockaddr *)&tor, sizeof(tor))) {
		close(s);
		return -1;
	}
	return s;
}

int
tor_connect(const uint8_t *h, uint8_t *p,
		uint8_t *th, uint8_t *tp,
		uint8_t *su, uint8_t *sp)
{
	int s = tor_socks_socket(th, tp);
	if (0 > s) goto fail;
	if (false == socks5_start(s)) goto fail;
	if (false == socks5_auth(s, su, sp)) goto fail;
	if (false == socks5_request(s, h, p)) goto fail;
	return s;
fail:
	if (0 > s) close(s);
	return -1;
}

/*
 * Gluster RPC packet inspector for testing the Wireshark dissector.
 * Copyright (c) 2011 Niels de Vos <ndevos@redhat.com>, Red Hat UK, Ltd.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

extern void gluster_decode_packet(unsigned char * pkt, size_t size);

int main(int argc, char **argv)
{
	size_t size = 0;
	unsigned char c, packet[2048];
	int fd;

	if (argc != 2) {
		printf("No file given.\n");
		exit(1);
	}
	printf("Reading from %s...\n", argv[1]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		printf("Failed ot open %s.\n", argv[1]);
		exit(1);
	}

	while (read(fd, &c, 1) != 0) {
		packet[size] = c;
		size++;
	}
	printf("Read %ld bytes.\n", size);

	gluster_decode_packet(packet, size);

	exit(0);
}


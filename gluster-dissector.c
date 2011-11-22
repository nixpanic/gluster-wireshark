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


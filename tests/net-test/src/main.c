#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


char *header =	"HTTP/1.1 200 OK\r\n" \
				"Cache-Control: no-cache\r\n" \
				"Server: net-test\r\n" \
				"Connection: Keep-Alive\r\n" \
				"Content-Type: text/html\r\n" \
				"\r\n";

static int v = 0;

#define ntmsg(verbose, fmt, ...)		\
	do {								\
		if (verbose <= v)				\
			printf(fmt, ##__VA_ARGS__);	\
	} while (0)

void print_help(void)
{
	printf("Usage: net-test -v [verbose level opt] -b (nonblock opt) -w [write-size arg] -c [write-count arg] -p [file-path arg]\n");
}

int main(int argc, char **argv)
{
	struct sockaddr_in saddr = { 0 };
	char *buffer, *path = NULL;
	int ret, srv, fd, fd2, i, n, c, cnt = 100;
	int nonblock = 0, writesz = 4096;

	while ((c = getopt(argc, argv, "v:bw:c:p:h")) != -1) {
		switch (c) {

		case 'b':
			nonblock = 1;
			break;
		case 'w':
			writesz = atoi(optarg);
			break;
		case 'c':
			cnt = atoi(optarg);
			break;
		case 'p':
			path = optarg;
			break;
		case 'v':
			v = atoi(optarg);
			break;
		case 'h':
			print_help();
			break;
		}
	}

	buffer = malloc(writesz);

	ntmsg(1, "-----------------------\n");	
	ntmsg(1, "test options:\n\twrite size %d\n\twrite count %d\n", writesz, cnt);
	if (nonblock)
		ntmsg(1, "\tnonblocking writes\n");
	if (path != NULL)
		ntmsg(1, "\tfile path %s\n", path);
	ntmsg(1, "-----------------------\n");	

	srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv == -1) {
		printf("socket error\n");
		return 0;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(80);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((ret = bind(srv, (struct sockaddr *) &saddr, sizeof(saddr))) < 0) {
		printf("bind error: %s\n", strerror(ret));
		return 0;
	}

	ret = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(int));

	if (listen(srv, 50) < 0) {
		printf("listen error\n");
		return 0;
	}

	ntmsg(2, "fill buffer\n");

	for (i = 0; i < writesz; i++)
		buffer[i] = i % 256;

	ntmsg(2, "wait for connection\n");
	socklen_t saddrsz = sizeof(saddr);

	if ((fd = accept4(srv, (struct sockaddr *)&saddr, &saddrsz, nonblock ? SOCK_NONBLOCK : 0)) < 0) {
		printf("accept error\n");
		goto error;
	}
	ntmsg(2, "connection accepted\n");

	write(fd, header, strlen(header));

	if (path != NULL) {
		ntmsg(2, "opening file %s\n", path);
		fd2 = open(path, O_RDONLY);
		if (fd2 > 0) {
			for (i = 0; i < cnt; i++) {
				if ((n = read(fd2, buffer, writesz)) <= 0)
					break;
				n = write(fd, buffer, n);
				if (nonblock && n < writesz) {
					ntmsg(2, "partial write %d (should be %d)\n", n, writesz);
					while (n < writesz)
						n += write(fd, buffer + n, writesz - n);
				}
			}

			close(fd2);
		}
	} else {
		for (i = 0; i < cnt; i++) {
			if ((n = write(fd, buffer, writesz)) <= 0)
				break;

			if (nonblock && n < writesz) {
				ntmsg(2, "partial write %d (should be %d)\n", n, writesz);
				while (n < writesz)
					n += write(fd, buffer + n, writesz - n);
			}
		}
	}
	close(fd);

error:
	close(srv);
	free(buffer);

	return 0;
}

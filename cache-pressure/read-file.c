#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static int done = 0;
static size_t BUFSIZE = 1024 * 1024;

void sig_handler(int signo)
{
	done = 1;
}

static ssize_t full_read(int fd, char *buf, size_t size)
{
	ssize_t ret = 0;

	while (ret < size) {
		ssize_t cur = read(fd, buf + ret, size - ret);
		if (cur <= 0) {
			if (!cur)
				return ret;
			return cur;
		}
		ret += cur;
	}
	return ret;
}

static unsigned long get_read_bytes(int fd, char *buf)
{
	ssize_t ret = full_read(fd, buf, BUFSIZE);
	unsigned long read_bytes = 123;
	int nr;

	if (ret < 0) {
		fprintf(stderr, "Failed to read our iofd\n");
		exit(1);
	}
	buf = strstr(buf, "read_bytes");
	if (!buf) {
		fprintf(stderr, "There's no read_bytes entry?\n");
		exit(1);
	}
	nr = sscanf(buf, "read_bytes: %lu\n", &read_bytes);
	if (nr != 1) {
		fprintf(stderr, "Couldn't find our read bytes, %d, %lu\n", nr, read_bytes);
		exit(1);
	}
	lseek(fd, 0, SEEK_SET);
	return read_bytes;
}

int main(int argc, char **argv)
{
	char *iofile;
	char *filename;
	char *buf;
	int fd, iofd;
	unsigned long read_bytes = 0, loops = 0, total_read = 0;
	pid_t pid = getpid();

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Couldn't register signal handler\n");
		exit(1);
	}

	if (argc != 2) {
		fprintf(stderr, "Please specify a file\n");
		exit(1);
	}
	filename = strdup(argv[1]);
	if (!filename) {
		fprintf(stderr, "Couldn't allocate memory\n");
		exit(1);
	}

	iofile = malloc(sizeof(char) * 64);
	if (!iofile) {
		fprintf(stderr, "Couldn't allocate a buffer for our iofile\n");
		exit(1);
	}

	if (snprintf(iofile, 64, "/proc/%d/io", pid) < 0) {
		fprintf(stderr, "Couldn't make our iofile string\n");
		exit(1);
	}

	iofd = open(iofile, O_RDONLY);
	if (iofd < 0) {
		fprintf(stderr, "Couldn't open our io file?\n");
		exit(1);
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open file\n");
		exit(1);
	}

	buf = malloc(BUFSIZE);
	if (!buf) {
		fprintf(stderr, "Couldn't allocate my buffer\n");
		exit(1);
	}

	read_bytes = get_read_bytes(iofd, buf);
	while (!done) {
		ssize_t bytes = full_read(fd, buf, BUFSIZE);
		if (bytes < 0) {
			fprintf(stderr, "Failed to read\n");
			exit(1);
		} else if (!bytes) {
			unsigned long bytes = get_read_bytes(iofd, buf);
			if (bytes != read_bytes)
				printf("%s: loop %lu read bytes is %lu\n",
				       filename, loops, bytes - read_bytes);
			total_read += bytes - read_bytes;
			read_bytes = bytes;
			lseek(fd, 0, SEEK_SET);
			loops++;
		}
	}
	printf("%s: total read during loops %lu\n", filename, total_read);
	return 0;
}

#define _GNU_SOURCE
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int file_fd;
static uint64_t filesize = 1024 * 1024 * 1024;
static uint64_t bs = 4096;
static int nr_threads = 32;
static int loops = 100000;

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define MAX(x, a) ((x) < (a) ? a : x)
#define MIN(x, a) ((x) < (a) ? x : a)

static void get_offset_size(uint64_t *offset, uint64_t *size)
{
	*size = (uint64_t)random() % filesize;
	*offset = (uint64_t)random() % filesize;
	*offset = MIN(ALIGN(*offset, bs), filesize - bs);
	*size = MAX(ALIGN(*size, bs), bs);
	*size = MIN(*size, filesize - *offset);
}

static void *sync_file(void *arg)
{
	int i, ret;

	for (i = 0; i < loops; i++) {
		uint64_t size, offset;
		get_offset_size(&offset, &size);

		ret = sync_file_range(file_fd, offset, size,
				SYNC_FILE_RANGE_WRITE);
		if (ret) {
			perror("Couldn't sync");
			break;
		}
	}
	return NULL;
}

static void *mwrite_file(void *arg)
{
	char fill = random();
	char *ptr = mmap(NULL, filesize, PROT_WRITE, MAP_SHARED, file_fd, 0);
	int i;

	if (ptr == MAP_FAILED) {
		perror("Mmap failed");
		return NULL;
	}

	for (i = 0; i < loops; i++) {
		uint64_t size, offset;
		get_offset_size(&offset, &size);
		size -= 1;

		memset(ptr + offset, fill, size);
	}
	return NULL;
}

static void *write_file(void *arg)
{
	char fill = random();
	char *buf;
	ssize_t ret;
	int i;

	buf = malloc(bs);
	if (!buf) {
		perror("Couldn't allocate temporary buffer");
		return NULL;
	}

	memset(buf, fill, bs);
	for (i = 0; i < loops; i++) {
		uint64_t size, offset;
		get_offset_size(&offset, &size);

		for (; offset < (offset + size); offset + bs) {
			ret = pwrite(file_fd, buf, bs, offset);
			if (ret < 0) {
				perror("Failed to write fd");
				goto out;
			}
		}
	}
out:
	free(buf);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t *threads;
	int i, ret;

	file_fd = open("testfile", O_CREAT|O_RDWR|O_TRUNC, 0644);
	if (file_fd < 0) {
		perror("Failed to open file_fd");
		return -1;
	}

	if (ftruncate(file_fd, filesize)) {
		perror("Ftruncate failed");
		return -1;
	}

	threads = malloc(sizeof(pthread_t) * nr_threads);
	if (!threads) {
		perror("Couldn't allocate threads array");
		return -1;
	}
	memset(threads, 0, sizeof(pthread_t) * nr_threads);

	for (i = 0; i < nr_threads - 1; i++) {
		if (i % 2)
			ret = pthread_create(&threads[i], NULL, write_file, NULL);
		else
			ret = pthread_create(&threads[i], NULL, mwrite_file, NULL);
		if (ret) {
			perror("Failed to create thread");
			goto out;
		}
	}
	ret = pthread_create(&threads[nr_threads - 1], NULL, sync_file, NULL);
	if (ret) {
		perror("Failed to create sync thread");
		goto out;
	}
out:
	for (i = 0; i < nr_threads; i++) {
		ret = pthread_join(threads[i], NULL);
		if (ret) {
			perror("Couldn't pthread_join");
			return -1;
		}
	}
	return 0;
}

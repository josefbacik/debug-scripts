#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/ioctl.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/limits.h>

#define u64 uint64_t

struct btrfs_usage {
	u64 data_free;
	u64 meta_free;
	u64 unallocated;
};

struct file_info {
	u64 size;
	struct file_info *next;
};

enum falloc_option {
	NO_FALLOC,
	FALLOC_NO_FILL,
	FALLOC_FILL,
};

static struct option long_options[] = {
	{"help",	no_argument,	0,	'h'},
	{NULL,		0,		NULL,	0},
};
const char *optstr = "h";

static char *path;
static int total_spaces = 0;
static int fs_fd;
static u64 fs_size = 0;
static int data_threads = 4;
static int oappend_threads = 4;
static int odirect_threads = 4;
static int falloc_threads = 4;
static int falloc_fill_threads = 0;
static int meta_threads = 0;
static int nr_loops = 100;

static pthread_cond_t fill_cond;
static pthread_cond_t ready_cond;
static pthread_mutex_t mutex;
static int filling_threads = 0;
static int ready = 0;
static int enospc_errors = 0;

char *buf = NULL;
u64 buf_size = 1024 * 1024 * 1024;

static void print_usage(char *cmd)
{
	printf("%s usage: %s [-h] /path", cmd, cmd);
}

static void filling_finished(void)
{
	pthread_mutex_lock(&mutex);
	filling_threads--;
	if (filling_threads == 0)
		pthread_cond_signal(&fill_cond);

	while (!ready)
		pthread_cond_wait(&ready_cond, &mutex);

	printf("ok starting\n");
	pthread_mutex_unlock(&mutex);
}

static void report_enospc_error(const char *thread_type, int thread_nr)
{
	fprintf(stderr, "%s: thread %d got an unexpected enospc error\n",
		thread_type, thread_nr);
	pthread_mutex_lock(&mutex);
	enospc_errors++;
	pthread_mutex_unlock(&mutex);
}

static int get_btrfs_usage(struct btrfs_usage *usage)
{
	struct btrfs_ioctl_space_args *sargs;
	struct btrfs_ioctl_space_info *sp;
	u64 mask = BTRFS_BLOCK_GROUP_TYPE_MASK | BTRFS_SPACE_INFO_GLOBAL_RSV;
	u64 used = 0;
	int ret, i;

	usage->data_free = 0;
	usage->meta_free = 0;
	usage->unallocated = 0;

	if (!total_spaces) {
		sargs = malloc(sizeof(struct btrfs_ioctl_space_args));
		if (!sargs) {
			fprintf(stderr, "Failed to alloc sargs\n");
			return -1;
		}
		sargs->space_slots = 0;
		sargs->total_spaces = 0;
		ret = ioctl(fs_fd, BTRFS_IOC_SPACE_INFO, sargs);
		if (ret < 0) {
			fprintf(stderr, "Failed to get space info %d (%s)\n",
				errno, strerror(errno));
			free(sargs);
			return -1;
		}
		total_spaces = sargs->total_spaces;
		free(sargs);
	}

	sargs = malloc(sizeof(struct btrfs_ioctl_space_args) +
		       (total_spaces * sizeof(struct btrfs_ioctl_space_info)));
	if (!sargs) {
		fprintf(stderr, "Failed to alloc sargs\n");
		return -1;
	}

	sargs->space_slots = total_spaces;
	sargs->total_spaces = 0;
	ret = ioctl(fs_fd, BTRFS_IOC_SPACE_INFO, sargs);
	if (ret < 0) {
		fprintf(stderr, "Failed to get space info %d (%s)\n",
			errno, strerror(errno));
		free(sargs);
		return -1;
	}

	sp = sargs->spaces;
	for (i = 0; i < sargs->total_spaces; i++, sp++) {
		u64 flags = sp->flags & mask;
		if (flags ==
		    (BTRFS_BLOCK_GROUP_DATA|BTRFS_BLOCK_GROUP_METADATA)) {
			usage->data_free += sp->total_bytes - sp->used_bytes;
			usage->meta_free += sp->total_bytes - sp->used_bytes;
		} else if (flags == BTRFS_BLOCK_GROUP_DATA) {
			usage->data_free = sp->total_bytes - sp->used_bytes;
		} else if (flags == BTRFS_BLOCK_GROUP_METADATA) {
			usage->meta_free += sp->total_bytes - sp->used_bytes;
		} else if (flags == BTRFS_SPACE_INFO_GLOBAL_RSV) {
			usage->meta_free -= sp->total_bytes;
		}

		if (flags != BTRFS_SPACE_INFO_GLOBAL_RSV)
			used += sp->total_bytes;
	}
	usage->unallocated = fs_size - used;
	free(sargs);
	return 0;
}

/*
 * Ideal we'd do something like search the chunks like btrfs filesystem usage
 * does, but this is close enough.
 */
static int get_fs_size(void)
{
	struct statfs buf;
	int ret = fstatfs(fs_fd, &buf);
	int bits;

	if (ret) {
		fprintf(stderr, "statfs failed: %d (%s)\n", errno,
			strerror(errno));
		return -1;
	}
	switch (buf.f_bsize) {
	case 4096:
		bits = 12;
		break;
	case 512:
		bits = 9;
		break;
	default:
		fprintf(stderr, "We don't have bits for that blocksize, pls fix\n");
		return -1;
	}

	fs_size = buf.f_blocks << bits;
	return 0;
}

#define FREE_THRESH (1024 * 1024 * 5)

static int check_early_enospc(void)
{
	struct btrfs_usage usage;

	get_btrfs_usage(&usage);

	printf("data_free %lu bytes, meta_free %lu bytes unallocated %lu\n",
	       usage.data_free, usage.meta_free, usage.unallocated);
	if (usage.data_free > FREE_THRESH || usage.meta_free > FREE_THRESH) {
		fprintf(stderr, "We have free data and metadata space\n");
		return -1;
	}

	if (usage.unallocated && (!usage.data_free || !usage.meta_free)) {
		/*
		 * Sometimes we don't allocate the last little bit because of
		 * alignment reasons.
		 */
		if (usage.unallocated <= FREE_THRESH)
			return 0;
		fprintf(stderr, "We still have unallocated space\n");
		return -1;
	}

	return 0;
}

static int create_thread_dir(int thread_nr)
{
	char file[PATH_MAX];
	int ret;

	snprintf(file, PATH_MAX, "%s/thread_%d", path, thread_nr);
	ret = mkdir(file, 0600);
	if (ret < 0) {
		fprintf(stderr, "failed to mkdir %s: %d (%s)\n",
			file, errno, strerror(errno));
		return -1;
	}

	return 0;
}

static size_t get_chunk(u64 write_amount, int small_chunk, int align)
{
	size_t chunk;

	if (write_amount < 4096)
		return write_amount;

	do {
		if (small_chunk)
			chunk = 4096;
		else
			chunk = random() % buf_size;

		if (align)
			chunk = (chunk + 4095) & (~4096);

		if (!chunk)
			continue;
		if (chunk > write_amount)
			chunk = write_amount;
	} while (chunk == 0);

	return chunk;
}

static int write_chunk(int fd, size_t amount, size_t *written)
{
	ssize_t ret;
	size_t pos = 0;

	while (amount) {
		ret = write(fd, buf+pos, amount);
		if (ret < 0) {
			if (errno != ENOSPC)
				fprintf(stderr, "failed to write: %d (%s)\n",
					errno, strerror(errno));
			return -1;
		}
		pos += ret;
		amount -= ret;
		*written += ret;
	}

	return 0;
}

static int write_file(int fd, u64 write_amount, u64 *written, int align)
{
	u64 total_written = 0;
	int ret;
	int small_chunk = 0;

	while ((write_amount == (u64)-1) || total_written < write_amount) {
		size_t chunk = get_chunk(write_amount, small_chunk, align);
		ret = write_chunk(fd, chunk, &total_written);
		if (ret) {
			if (errno != ENOSPC || small_chunk ||
			    write_amount != (u64)-1)
				break;
			small_chunk = 1;
		}
	}

	if (write_amount == (u64)-1)
		*written = total_written;

	return ret;
}

static int falloc_file(int fd, u64 write_amount, u64 *written)
{
	u64 pos = 0;
	u64 total_written = 0;
	int small_chunk = 0;
	int ret;

	while ((write_amount == (u64)-1) || total_written < write_amount) {
		size_t chunk = get_chunk(write_amount, small_chunk, 1);

		ret = fallocate(fd, 0, pos, chunk);
		if (ret < 0) {
			if (errno != ENOSPC || small_chunk ||
			    write_amount != (u64)-1)
				break;
			small_chunk = 1;
		} else {
			total_written += chunk;
			pos += chunk;
		}
	}

	if (write_amount == (u64)-1)
		*written = total_written;

	return ret;
}

static void fill_file(const char *thread_type, int thread_nr, int flags,
		      int align, enum falloc_option falloc)
{
	u64 write_amount = (u64)-1;
	u64 written;
	int loops = nr_loops;
	char file[PATH_MAX];
	int fd;
	int ret;

	if (create_thread_dir(thread_nr))
		return;

	snprintf(file, PATH_MAX, "%s/thread_%d/file", path, thread_nr);

	do {
		fd = open(file, flags, 0600);
		if (fd < 0) {
			fprintf(stderr, "failed to open %s: %d (%s)\n", file,
				errno, strerror(errno));
			break;
		}

		if (falloc != NO_FALLOC) {
			ret = falloc_file(fd, write_amount, &written);
			if (ret < 0 && errno == ENOSPC) {
				if (write_amount != (u64)-1) {
					report_enospc_error(thread_type,
							    thread_nr);
					break;
				} else if (falloc == FALLOC_NO_FILL) {
					filling_finished();
				}
				write_amount = written;
			} else if (ret < 0) {
				break;
			}
		}

		ret = write_file(fd, write_amount, &written, align);
		if (ret < 0 && errno == ENOSPC) {
			if (write_amount != (u64)-1) {
				report_enospc_error(thread_type, thread_nr);
				break;
			} else {
				filling_finished();
			}
			write_amount = written;
		} else if (ret < 0) {
			break;
		}

		ret = fsync(fd);
		if (ret < 0) {
			fprintf(stderr, "fsync failed in write thread: %d (%s)\n",
				errno, strerror(errno));
			break;
		}
		close(fd);
		unlink(file);
	} while (!enospc_errors && (!loops || (--loops > 0)));
}

static int generate_small_files(int thread_nr, int nr_files)
{
	char file[PATH_MAX];
	int files_created = 0;
	int fd;

	do {
		snprintf(file, PATH_MAX, "%s/thread_%d/file_%d", path,
			 thread_nr, files_created);
		fd = open(file, O_WRONLY|O_CREAT, 0600);
		if (fd < 0)
			break;
		close(fd);
		files_created++;
	} while (!enospc_errors &&
		 ((nr_files == -1) || files_created < nr_files));

	return files_created;
}

static void *data_writer(void *arg)
{
	int thread_nr = *(int *)arg;

	printf("starting thread %d\n", thread_nr);
	fill_file("data writer", thread_nr, O_CREAT|O_WRONLY, 0, NO_FALLOC);
	return NULL;
}

static void *oappend_writer(void *arg)
{
	int thread_nr = *(int *)arg;

	printf("starting thread %d\n", thread_nr);
	fill_file("oappend writer", thread_nr, O_CREAT|O_WRONLY|O_APPEND, 0, NO_FALLOC);
	return NULL;
}

static void *odirect_writer(void *arg)
{
	int thread_nr = *(int *)arg;

	printf("starting thread %d\n", thread_nr);
	fill_file("odirect writer", thread_nr, O_CREAT|O_WRONLY|O_DIRECT, 1, NO_FALLOC);
	return NULL;
}

static void *falloc_nofill(void *arg)
{
	int thread_nr = *(int *)arg;

	printf("starting thread %d\n", thread_nr);
	fill_file("falloc nofill", thread_nr, O_CREAT|O_WRONLY, 0, FALLOC_NO_FILL);
	return NULL;
}

static void *falloc_fill(void *arg)
{
	int thread_nr = *(int *)arg;

	printf("starting thread %d\n", thread_nr);
	fill_file("falloc fill", thread_nr, O_CREAT|O_WRONLY, 0, FALLOC_FILL);
	return NULL;
}

static void *meta_writer(void *arg)
{
	char file[PATH_MAX];
	int thread_nr = *(int *)arg;
	int nr_files;
	int loops = nr_loops, i, ret;

	if (create_thread_dir(thread_nr))
		return NULL;

	nr_files = generate_small_files(thread_nr, -1);
	printf("meta writer finished %d waiting\n", thread_nr);
	filling_finished();

	do {
		for (i = 0; i < nr_files; i++) {
			snprintf(file, PATH_MAX, "%s/thread_%d/file_%d", path,
				 thread_nr, i);
			ret = unlink(file);
			if (ret) {
				report_enospc_error("meta writer", thread_nr);
				break;
			}
		}

		ret = generate_small_files(thread_nr, nr_files);
		if (ret != nr_files) {
			report_enospc_error("meta writer", thread_nr);
			break;
		}
	} while (!enospc_errors && (!loops || (--loops > 0)));

	return NULL;
}

static int start_threads(pthread_t *threads, int *thread_nr)
{
	int i = 0, c = 0;
	int ret;

	for (c = 0; c < data_threads; i++,c++) {
		thread_nr[i] = i;
		ret = pthread_create(&threads[i], NULL, data_writer,
				     &thread_nr[i]);
		if (ret) {
			fprintf(stderr, "Failed to start threads: %d (%s)\n",
				errno, strerror(errno));
			return -1;
		}
	}
	for (c = 0; c < oappend_threads; i++,c++) {
		thread_nr[i] = i;
		ret = pthread_create(&threads[i], NULL, oappend_writer,
				     &thread_nr[i]);
		if (ret) {
			fprintf(stderr, "Failed to start threads: %d (%s)\n",
				errno, strerror(errno));
			return -1;
		}
	}
	for (c = 0; c < odirect_threads; i++,c++) {
		thread_nr[i] = i;
		ret = pthread_create(&threads[i], NULL, odirect_writer,
				     &thread_nr[i]);
		if (ret) {
			fprintf(stderr, "Failed to start threads: %d (%s)\n",
				errno, strerror(errno));
			return -1;
		}
	}
	for (c = 0; c < falloc_threads; i++,c++) {
		thread_nr[i] = i;
		ret = pthread_create(&threads[i], NULL, falloc_nofill,
				     &thread_nr[i]);
		if (ret) {
			fprintf(stderr, "Failed to start threads: %d (%s)\n",
				errno, strerror(errno));
			return -1;
		}
	}
	for (c = 0; c < falloc_fill_threads; i++,c++) {
		thread_nr[i] = i;
		ret = pthread_create(&threads[i], NULL, falloc_fill,
				     &thread_nr[i]);
		if (ret) {
			fprintf(stderr, "Failed to start threads: %d (%s)\n",
				errno, strerror(errno));
			return -1;
		}
	}
	for (c = 0; c < meta_threads; i++,c++) {
		thread_nr[i] = i;
		ret = pthread_create(&threads[i], NULL, meta_writer,
				     &thread_nr[i]);
		if (ret) {
			fprintf(stderr, "Failed to start threads: %d (%s)\n",
				errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int fill_buf(void)
{
	ssize_t ret;
	size_t total_read = 0, pos = 0;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Couldn't open /dev/urandom: %d (%s)\n",
			errno, strerror(errno));
		return -1;
	}

	while (total_read < buf_size) {
		ret = read(fd, buf + pos, buf_size - total_read);
		if (ret < 0) {
			fprintf(stderr, "Couldn't read from urandom: %d (%s)\n",
				errno, strerror(errno));
			close(fd);
			return -1;
		}
		total_read += ret;
		pos += ret;
	}
	close(fd);
	return 0;
}

static int init_conds(void)
{
	int ret;

	ret = pthread_cond_init(&fill_cond, NULL);
	if (ret) {
		fprintf(stderr, "Couldn't init fill cond: %d (%s)\n", errno,
			strerror(errno));
		return -1;
	}

	ret = pthread_cond_init(&ready_cond, NULL);
	if (ret) {
		fprintf(stderr, "Couldn't init ready cond: %d (%s)\n", errno,
			strerror(errno));
		pthread_cond_destroy(&fill_cond);
		return -1;
	}

	ret = pthread_mutex_init(&mutex, NULL);
	if (ret) {
		fprintf(stderr, "Couldn't init fill mutex: %d (%s)\n", errno,
			strerror(errno));
		pthread_cond_destroy(&fill_cond);
		pthread_cond_destroy(&ready_cond);
		return -1;
	}
	return 0;
}

static void kill_threads(pthread_t *threads, int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (!threads[i])
			break;
		printf("killing thread %d\n", (int)threads[i]);
		pthread_kill(threads[i], SIGKILL);
	}

	for (i = 0; i < nr; i++) {
		if (!threads[i])
			break;
		pthread_join(threads[i], NULL);
	}
}

int main(int argc, char **argv)
{
	struct btrfs_usage usage;
	pthread_t *threads;
	int *thread_nr;
	int ret;
	int opt;
	int total_threads = 0;
	int i;

	while ((opt =
		getopt_long(argc, argv, optstr, long_options, NULL) != -1)) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		print_usage(argv[0]);
		return 1;
	}

	path = argv[optind];
	fs_fd = open(path, O_RDONLY);
	if (fs_fd < 0) {
		fprintf(stderr, "Couldn't open %s: %d (%s)\n", argv[optind],
			errno, strerror(errno));
		return 1;
	}

	ret = get_fs_size();
	if (ret)
		goto out;

	ret = get_btrfs_usage(&usage);
	if (ret)
		goto out;

	total_threads = data_threads + oappend_threads + falloc_threads +
		meta_threads + falloc_fill_threads + odirect_threads;

	filling_threads = total_threads;

	threads = calloc(total_threads, sizeof(pthread_t));
	if (!threads) {
		fprintf(stderr, "Couldn't allocate threads array\n");
		goto out;
	}

	thread_nr = calloc(total_threads, sizeof(int));
	if (!thread_nr) {
		fprintf(stderr, "Couldn't allocate thread nr array\n");
		free(threads);
		goto out;
	}

	ret = posix_memalign((void **)&buf, 4096, buf_size);
	if (ret < 0) {
		fprintf(stderr, "Couldn't allocate the fill buffer\n");
		free(thread_nr);
		free(threads);
		goto out;
	}

	ret = fill_buf();
	if (ret)
		goto out_free;

	ret = init_conds();
	if (ret)
		goto out_free;

	ret = start_threads(threads, thread_nr);
	if (ret) {
		kill_threads(threads, total_threads);
		goto out_threads;
	}

	pthread_mutex_lock(&mutex);
	while (filling_threads)
		pthread_cond_wait(&fill_cond, &mutex);

	ret = check_early_enospc();
	if (ret) {
		pthread_mutex_unlock(&mutex);
		kill_threads(threads, total_threads);
		goto out_threads;
	}
	printf("setting ready\n");
	ready = 1;
	pthread_cond_broadcast(&ready_cond);
	pthread_mutex_unlock(&mutex);

	for (i = 0; i < total_threads; i++) {
		if (!threads[i]) {
			printf("huh?\n");
			continue;
		}
		printf("waiting on thread %d\n", (int)threads[i]);
		pthread_join(threads[i], NULL);
	}

	if (enospc_errors) {
		fprintf(stderr, "We had %d enospc errors\n", enospc_errors);
		ret = -1;
	}
out_threads:
	pthread_cond_destroy(&fill_cond);
	pthread_cond_destroy(&ready_cond);
	pthread_mutex_destroy(&mutex);
out_free:
	free(buf);
	free(threads);
	free(thread_nr);
out:
	close(fs_fd);
	return ret ? 1 : 0;
}

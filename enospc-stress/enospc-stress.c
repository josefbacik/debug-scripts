#include <bpf/libbpf.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <libgen.h>
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

#include "enospc-stress.skel.h"
#include "common.h"

#ifndef u64
#define u64 uint64_t
#endif

struct create_args {
	const char *type;
	int thread_nr;
	int flags;
	int nr_files;
	unsigned align:1;
	unsigned setup:1;
	unsigned falloc:1;
	unsigned fill:1;
};

struct file_info {
	u64 size;
	struct file_info *next;
};

static struct option long_options[] = {
	{"help",		no_argument,		0,	'h'},
	{"meta-threads",	required_argument,	0,	'm'},
	{"data-threads",	required_argument,	0,	'd'},
	{"direct-threads",	required_argument,	0,	'D'},
	{"oappend-threads",	required_argument,	0,	'o'},
	{"falloc-threads",	required_argument,	0,	'f'},
	{"falloc-fill-threads",	required_argument,	0,	'F'},
	{"runtime",		required_argument,	0,	'r'},
	{"bufsize",		required_argument,	0,	'b'},
	{NULL,		0,		NULL,	0},
};
const char *optstr = "hm:d:D:o:f:F:r:b:";

static char *path;
static int fs_fd;
static int data_threads = 4;
static int oappend_threads = 4;
static int odirect_threads = 4;
static int falloc_threads = 4;
static int falloc_fill_threads = 0;
static int meta_threads = 4;
static int runtime = 120;

static pthread_cond_t fill_cond;
static pthread_cond_t ready_cond;
static pthread_mutex_t mutex;
static int filling_threads = 0;
static int ready = 0;
static int enospc_errors = 0;
static struct timeval start;
static struct ring_buffer *rb = NULL;
static u64 free_thresh = 0;

char *buf = NULL;
u64 buf_size = 128 * 1024 * 1024;

static void print_giant_text(char *text)
{
	char line[81];
	char *cur, *prev, *first;
	unsigned len;

	cur = first = text;
	while ((cur = strchr(cur, ' ')) != NULL) {

		if (cur - first < 80) {
			prev = cur;
			cur++;
			continue;
		}

		len = prev - first;
		memcpy(line, first, len);
		line[len] = '\n';
		line[len + 1] = '\0';
		printf(line);
		first = prev + 1;
		prev = cur;
		cur++;
	}

	if (prev != first) {
		len = prev - first;
		memcpy(line, first, len);
		line[len] = '\n';
		line[len + 1] = '\0';
		printf(line);
	}
}

static char *help_msg =
	"All threads default to 4, with the exception of falloc-fill. The "
	"way btrfs's enospc system works is we assume we can't fill prealloc "
	"area and will reserve anyway, and then check for real if we "
	"fail the reservation. This means with falloc-fill we'll easily "
	"allocate the whole drive as data before metadata can catch up "
	"which makes the test not really work as expected if you have "
	"small test devices.  Only use it if you're spefically testing "
	"falloc-fill scenarios with a large enough device. "
	"The buffer is seeded with /dev/urandom. "
	"All threads create new files and write to them on each loop, "
	"with the exception of the O_APPEND threads which will fill "
	"one file per threads. Each write is a random size of the overall "
	"buffer size, so we will write between 1 and BUFSIZE bytes.";

static void print_usage(char *cmd)
{
	printf("%s usage: %s [options] /path\n", basename(cmd), basename(cmd));
	printf("where [options] can be any of\n");
	printf("\t--help,-h\t\t\tPrint this message.\n");
	printf("\t--meta-threads,-m\t\tNumber of metadata filler threads.\n");
	printf("\t--data-threads,-d\t\tNumber of data filler threads.\n");
	printf("\t--direct-threads,-D\t\tNumber of O_DIRECT data filler threads.\n");
	printf("\t--oappend-threads,-o\t\tNumber of O_APPEND data filler threads.\n");
	printf("\t--falloc-threads,-f\t\tNumber of fallocate() filler threads.\n");
	printf("\t--falloc-fill-threads,-F\tNumber of fallocate() and then fill filler threads.\n");
	printf("\t--runtime,-r\t\t\tNumber of seconds to run (120 by default).\n");
	printf("\t--bufsize,-b\t\t\tThe size of the buffer to use for writing in MiB (1GiB by default).\n");
	printf("\n");
	print_giant_text(help_msg);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int add_file_info(struct create_args *args, struct file_info **head,
			 u64 written)
{
	struct file_info *file = malloc(sizeof(struct file_info));
	if (!file)
		return -1;
	file->size = written;
	file->next = *head;
	*head = file;
	args->nr_files++;
	return 0;
}

static void trim_files(struct create_args *args, struct file_info **head)
{
	int to_cull;

	if (args->fill || args->falloc)
		return;

	to_cull = args->nr_files >> 2;

	while (to_cull) {
		struct file_info *file = *head;
		*head = file->next;
		free(file);
		to_cull--;
	}
}

static void free_files(struct create_args *args, struct file_info **head)
{
	struct file_info *file;
	int nr = 0;
	u64 size = 0;

	while (*head) {
		file = *head;
		*head = file->next;
		nr++;
		size += file->size;
		free(file);
	}

	printf("%s thread %d had %d files writing %lu bytes\n",
	       args->type, args->thread_nr, nr, size);
}

static void filling_finished(void)
{
	pthread_mutex_lock(&mutex);
	filling_threads--;
	if (filling_threads == 0)
		pthread_cond_signal(&fill_cond);

	while (!ready)
		pthread_cond_wait(&ready_cond, &mutex);

	pthread_mutex_unlock(&mutex);
}

static void report_enospc_error(const char *thread_type, const char *op,
				int thread_nr)
{
	fprintf(stderr, "%s: thread %d got an unexpected enospc error doing %s\n",
		thread_type, thread_nr, op);
	pthread_mutex_lock(&mutex);
	enospc_errors++;
	pthread_mutex_unlock(&mutex);
}

static int finished(void)
{
	struct timeval cur;
	int delta;

	if (!runtime)
		return 0;

	gettimeofday(&cur, NULL);
	delta = cur.tv_sec - start.tv_sec;
	return delta >= runtime;
}

#define FREE_THRESH (1024 * 1024 * 5)

static u64 get_total_used(const struct event *e)
{
	return e->bytes_used + e->bytes_pinned + e->bytes_may_use +
		e->bytes_reserved + e->bytes_readonly;
}

static void dump_event(const struct event *e)
{
	fprintf(stderr, "Dumping failed tickets event\n");
	fprintf(stderr, "flags=%lu total_bytes=%lu used=%lu pinned=%lu may_use=%lu reserved=%lu readonly=%lu global_rsv=%lu trans_rsv=%lu delayed_refs_rsv=%lu delayed_rsv=%lu\n",
		e->flags, e->total_bytes, e->bytes_used, e->bytes_pinned,
		e->bytes_may_use, e->bytes_reserved, e->bytes_readonly,
		e->global_rsv, e->trans_rsv, e->delayed_refs_rsv,
		e->delayed_rsv);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = (const struct event *)data;
	u64 used = get_total_used(e);

	dump_event(e);

	if (e->total_bytes > used &&
	    ((e->total_bytes - used) > free_thresh)) {
		fprintf(stderr, "Too much space left\n");
		enospc_errors++;
	}

	if (e->flags & BTRFS_BLOCK_GROUP_METADATA) {
		if (e->bytes_may_use != e->global_rsv) {
			fprintf(stderr, "We have more may_use than the global_rsv\n");
			enospc_errors++;
		}
	}

	return 0;
}

void safe_poll_events(u64 written)
{
	pthread_mutex_lock(&mutex);
	free_thresh = written + FREE_THRESH;
	ring_buffer__poll(rb, 100);
	pthread_mutex_unlock(&mutex);
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

static size_t get_chunk(struct create_args *args, struct file_info *file)
{
	size_t chunk;

	if (file)
		return file->size;

	if (args && !args->fill && !args->falloc)
		return 0;

	do {
		chunk = random() % buf_size;
		if (args && args->align)
			chunk = (chunk + 4095) & (~4096);
	} while (chunk == 0);

	return chunk;
}

static int write_chunk(int fd, size_t amount)
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
	}

	return 0;
}

static u64 write_file(int fd, u64 write_amount)
{
	u64 total_written = 0;
	int ret;

	while ((write_amount == (u64)-1) || total_written < write_amount) {
		size_t chunk = get_chunk(NULL, NULL);
		if (chunk > (write_amount - total_written))
			chunk = write_amount - total_written;
		ret = write_chunk(fd, chunk);
		if (ret)
			return total_written;
		total_written += chunk;
	}

	return total_written;
}

static void *oappend_writer(void *arg)
{
	int thread_nr = *(int *)arg;
	u64 write_amount = (u64)-1;
	u64 written;
	char file[PATH_MAX];
	int fd;
	int ret;

	if (create_thread_dir(thread_nr))
		return NULL;

	snprintf(file, PATH_MAX, "%s/thread_%d/file", path, thread_nr);

	do {
		if (write_amount != (u64)-1) {
			ret = unlink(file);
			if (ret) {
				report_enospc_error("oappend writer", "unlink",
						    thread_nr);
				break;
			}
		}

		fd = open(file, O_CREAT|O_WRONLY|O_APPEND, 0600);
		if (fd < 0) {
			fprintf(stderr, "failed to open %s: %d (%s)\n", file,
				errno, strerror(errno));
			break;
		}

		written = write_file(fd, write_amount);
		if (write_amount == (u64)-1) {
			fsync(fd);
			filling_finished();
			write_amount = written;
		} else if (written != write_amount) {
			safe_poll_events(write_amount);
		}

		close(fd);
	} while (!enospc_errors && !finished());

	return NULL;
}

static int generate_files(struct create_args *args, struct file_info **head)
{
	struct file_info *file = *head;
	char name[PATH_MAX];
	int files_created = 0;
	int fd;
	int ret = 0;

	if (args->setup) {
		if (create_thread_dir(args->thread_nr))
			return -1;
	} else {
		file = *head;
	}

	do {
		size_t written = get_chunk(args, file);

		snprintf(name, PATH_MAX, "%s/thread_%d/file_%d", path,
			 args->thread_nr, files_created);
		ret = 0;
		fd = open(name, args->flags, 0600);
		if (fd < 0) {
			if (errno == ENOSPC)
				safe_poll_events(0);
			else
				return -1;
			break;
		}

		if (args->falloc) {
			ret = fallocate(fd, 0, 0, written);
			if (ret) {
				safe_poll_events(written);
				break;
			}
		}

		if (args->fill) {
			ret = write_chunk(fd, written);
			if (ret) {
				safe_poll_events(written);
				break;
			}
		}

		/*
		 * We fsync() so we can have a stable amount of stuff on disk
		 * during setup, and then we know once we're done setting up
		 * we'll really be able to store everything on disk.
		 */
		if (args->setup && args->fill) {
			ret = fsync(fd);
			if (ret) {
				safe_poll_events(0);
				break;
			}
		}
		close(fd);

		if (args->setup) {
			ret = add_file_info(args, head, written);
			if (ret) {
				fprintf(stderr, "Ran out of memory for files\n");
				return ret;
			}
		} else {
			file = file->next;
		}
		files_created++;
	} while (!enospc_errors & (args->setup || file));

	return 0;
}

static int unlink_files(struct create_args *args, struct file_info *file)
{
	char name[PATH_MAX];
	int ret = 0, i;

	for (i = 0; file; file = file->next, i++) {
		snprintf(name, PATH_MAX, "%s/thread_%d/file_%d", path,
			 args->thread_nr, i);
		ret = unlink(name);
		if (ret) {
			if (errno == ENOENT) {
				errno = 0;
				ret = 0;
			}
			break;
		}
	}
	return ret;
}

static int create_files_thread(struct create_args *args)
{
	struct file_info *head = NULL;
	int ret;
	int need_trim = 1;

	printf("%s starting thread %d\n", args->type, args->thread_nr);

	args->setup = 1;
	ret = generate_files(args, &head);
	if (ret && errno != ENOSPC) {
		fprintf(stderr, "%s thread %d failed: %d (%s)\n",
			args->type, args->thread_nr, errno, strerror(errno));
		return -1;
	}
	filling_finished();

	if (head == NULL) {
		printf("%s: thread %d didn't get any fils setup during setup "
		       "phase, exiting\n", args->type, args->thread_nr);
		return 0;
	}

	args->setup = 0;

	do {
		ret = unlink_files(args, head);
		if (ret) {
			report_enospc_error(args->type, "unlink",
					    args->thread_nr);
			break;
		}

		if (need_trim) {
			trim_files(args, &head);
			need_trim = 0;
		}

		ret = generate_files(args, &head);
		if (ret)
			break;
	} while (!enospc_errors && !finished());

	free_files(args, &head);

	return ret;
}

static void *data_writer(void *arg)
{
	struct create_args args = {
		.type = "data writer",
		.thread_nr = *(int *)arg,
		.flags = O_CREAT|O_WRONLY,
		.fill = 1,
	};

	create_files_thread(&args);
	return NULL;
}

static void *odirect_writer(void *arg)
{
	struct create_args args = {
		.type = "odirect writer",
		.thread_nr = *(int *)arg,
		.flags = O_CREAT|O_WRONLY|O_DIRECT,
		.align = 1,
		.fill = 1,
	};

	create_files_thread(&args);
	return NULL;
}

static void *falloc_nofill(void *arg)
{
	struct create_args args = {
		.type = "falloc no fill",
		.thread_nr = *(int *)arg,
		.flags = O_CREAT|O_WRONLY,
		.falloc = 1,
	};

	create_files_thread(&args);
	return NULL;
}

static void *falloc_fill(void *arg)
{
	struct create_args args = {
		.type = "falloc fill",
		.thread_nr = *(int *)arg,
		.flags = O_CREAT|O_WRONLY,
		.falloc = 1,
		.fill = 1,
	};

	create_files_thread(&args);
	return NULL;
}

static void *meta_writer(void *arg)
{
	struct create_args args = {
		.type = "meta writer",
		.thread_nr = *(int *)arg,
		.flags = O_CREAT|O_WRONLY,
	};

	create_files_thread(&args);
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
	struct enospc_stress_bpf *skel;
	pthread_t *threads;
	int *thread_nr;
	int ret;
	int opt;
	int total_threads = 0;
	int i;

	while ((opt =
		getopt_long(argc, argv, optstr, long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			return 0;
		case 'm':
			meta_threads = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for threads\n");
				return 1;
			}
			break;
		case 'd':
			data_threads = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for threads\n");
				return 1;
			}
			break;
		case 'D':
			odirect_threads = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for threads\n");
				return 1;
			}
			break;
		case 'f':
			falloc_threads = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for threads\n");
				return 1;
			}
			break;
		case 'F':
			falloc_fill_threads = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for threads\n");
				return 1;
			}
			break;
		case 'o':
			oappend_threads = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for threads\n");
				return 1;
			}
			break;
		case 'r':
			runtime = (int)strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for runtime\n");
				return 1;
			}
			break;
		case 'b':
			buf_size = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "must specify an int for bufsize\n");
				return 1;
			}
			buf_size *= 1024 * 1024;
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		print_usage(argv[0]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();

	skel = enospc_stress_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	ret = enospc_stress_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL,
			      NULL);
	if (!rb) {
		ret = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto out;
	}

	path = argv[optind];
	fs_fd = open(path, O_RDONLY);
	if (fs_fd < 0) {
		fprintf(stderr, "Couldn't open %s: %d (%s)\n", argv[optind],
			errno, strerror(errno));
		ret = -11;
		goto out;
	}

	total_threads = data_threads + oappend_threads + falloc_threads +
		meta_threads + falloc_fill_threads + odirect_threads;

	filling_threads = total_threads;

	threads = calloc(total_threads, sizeof(pthread_t));
	if (!threads) {
		fprintf(stderr, "Couldn't allocate threads array\n");
		goto out_fd;
	}

	thread_nr = calloc(total_threads, sizeof(int));
	if (!thread_nr) {
		fprintf(stderr, "Couldn't allocate thread nr array\n");
		free(threads);
		goto out_fd;
	}

	ret = posix_memalign((void **)&buf, 4096, buf_size);
	if (ret < 0) {
		fprintf(stderr, "Couldn't allocate the fill buffer\n");
		free(thread_nr);
		free(threads);
		goto out_fd;
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

	ret = ring_buffer__poll(rb, 100);
	if (ret < 0 || enospc_errors) {
		printf("ret is %d enospc_errors is %d\n", ret, enospc_errors);
		pthread_mutex_unlock(&mutex);
		kill_threads(threads, total_threads);
		goto out_threads;
	}
	printf("setting ready\n");
	ready = 1;
	gettimeofday(&start, NULL);
	pthread_cond_broadcast(&ready_cond);
	pthread_mutex_unlock(&mutex);

	for (i = 0; i < total_threads; i++) {
		if (!threads[i])
			continue;
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
out_fd:
	close(fs_fd);
out:
	ring_buffer__free(rb);
	enospc_stress_bpf__destroy(skel);

	return ret ? 1 : 0;
}

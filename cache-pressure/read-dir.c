#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

static int done = 0;

void sig_handler(int signo)
{
	done = 1;
}

int main(int argc, char **argv)
{
	char *dirname;
	DIR *dir;
	char pathbuf[PATH_MAX];
	unsigned long loops = 0;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Couldn't register signal handler\n");
		exit(1);
	}

	if (argc != 2) {
		fprintf(stderr, "Please specify a file\n");
		exit(1);
	}
	dirname = strdup(argv[1]);
	if (!dirname) {
		fprintf(stderr, "Couldn't allocate memory\n");
		exit(1);
	}

	dir = opendir(dirname);
	if (!dir) {
		fprintf(stderr, "Couldn't open dir %s\n", dirname);
		exit(1);
	}

	while (!done) {
		struct dirent *dirent;
        struct stat st;

		errno = 0;
		dirent = readdir(dir);
		if (!dirent && errno == 0) {
			rewinddir(dir);
			loops++;
			continue;
		} else if (!dirent) {
			fprintf(stderr, "%s: failed to readdir\n", dirname);
			exit(1);
		}
		if (dirent->d_type != DT_REG)
			continue;
		snprintf(pathbuf, PATH_MAX, "%s/%s", dirname, dirent->d_name);
        if (stat(pathbuf, &st)) {
            fprintf(stderr, "%s: failed to stat\n", pathbuf);
            exit(1);
        }
	}
	printf("%s: total loops %lu\n", dirname, loops);
	return 0;
}

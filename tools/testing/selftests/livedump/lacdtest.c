// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <malloc.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>

const char *iotmp = "/tmp/lacdtest.XXXXXX";

int do_io(volatile bool *term, void *dummy)
{
	while (!*term) {
		char *fname = malloc(strlen(iotmp) + 1);
		int fd, i;

		strcpy(fname, iotmp);
		fd = mkstemp(fname);
		if (fd == -1) {
			fprintf(stderr, "Error creating tmp file: %s\n",
				strerror(errno));
			sleep(1);
			continue;
		}

		for (i = 0; i < 1000; i++)
			write(fd, fname, strlen(fname));

		close(fd);

		unlink(fname);
		free(fname);
	}

	return 0;
}

void *spawn(void *dummy)
{
	return NULL;
}

int spawner(volatile bool *term, void *dummy)
{
	pthread_t th;

	while (!*term) {
		int rv = pthread_create(&th, NULL, spawn, NULL);
		if (!rv)
			pthread_join(th, NULL);
		else
			sleep(1);
	}

	return 0;
}

int alloc_sprintf(char **str, const char *fmt, ...)
{
	int len;
	va_list ap;
	char *s;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (len < 0)
		return -1;

	len++;
	s = malloc(len);
	if (!s)
		return -1;

	va_start(ap, fmt);
	len = vsnprintf(s, len, fmt, ap);
	va_end(ap);

	if (len < 0) {
		free(s);
		return -1;
	}

	*str = s;
	return len;
}

const char *dumpstr = "core_limit=0\n";

int coredump_proc(const char *name, int pid)
{
	char *fname;
	int rv, fd;

	if (name && pid)
		rv = alloc_sprintf(&fname, "/proc/%s/%d/livedump", name, pid);
	else if (name)
		rv = alloc_sprintf(&fname, "/proc/%s/livedump", name);
	else
		rv = alloc_sprintf(&fname, "/proc/%d/livedump", pid);
	if (rv == -1) {
		fprintf(stderr, "Error allocating filename: %s\n",
			strerror(errno));
		return -1;
	}

	fd = open(fname, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "Error opening '%s': %s\n", fname,
			strerror(errno));
		free(fname);
		return -1;
	}
	free(fname);

	rv = write(fd, dumpstr, strlen(dumpstr));
	if (rv == -1) {
		fprintf(stderr, "Error writing to '%s': %s\n", fname,
			strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

int coredump_self(void)
{
	return coredump_proc("self", 0);
}

int coredump_from_fork(void)
{
	pid_t pid = getpid();
	pid_t rv;
	int status;

	rv = fork();
	if (rv == -1) {
		fprintf(stderr, "Error from fork: %s\n", strerror(errno));
		return -1;
	}
	if (rv == 0) {
		/* Child process, just do the coredump and exit. */
		rv = coredump_proc(NULL, pid);
		if (rv == -1)
			exit(1);
		exit(0);
	} else {
		pid = waitpid(rv, &status, 0);
		if (pid < 0) {
			fprintf(stderr, "Error waiting for pid: %s\n",
				strerror(errno));
			return -1;
		}
	}

	return 0;
}

static void *coredump_th(void *dummy)
{
	int rv = coredump_proc("self", 0);

	return ((void *) (long) rv);
}

int coredump_from_th(void)
{
	int rv;
	pthread_t th;
	void *data;

	rv = pthread_create(&th, NULL, coredump_th, NULL);
	if (rv) {
		fprintf(stderr, "pthread_create on dumper failed: %s\n",
			strerror(rv));
		return -1;
	}

	rv = pthread_join(th, &data);
	if (rv) {
		fprintf(stderr,
			"pthread_join on dumper failed: %s\n",
			strerror(rv));
	} else {
		rv = (long) data;
		if (rv)
			return -1;
	}

	return 0;
}

struct coredump_th_data;

struct per_th_data {
	struct coredump_th_data *d;
	pthread_t tid;
	int result;
};

struct coredump_th_data {
	int (*op)(volatile bool *term, void *data);
	void *data; /* User data */

	volatile bool terminate;
	struct per_th_data *thd;
	int (*do_coredump)(void);
	int dump_result;
};

void *th_run_op(void *dptr)
{
	struct per_th_data *thd = dptr;
	struct coredump_th_data *d = thd->d;

	thd->result = d->op(&d->terminate, d->data);
	return NULL;
}

int iterate_coredumps(int iterations, int (*do_coredump)(void))
{
	int rv = 0;
	int nsuccess = 0, nerrs = 0;
	int column = 80;

	if (iterations == 1)
		return do_coredump();

	while (iterations != 0) {
		rv = do_coredump();
		if (rv == -1) {
			if (errno == EINPROGRESS) {
				nerrs++;
				fwrite("P", 1, 1, stdout);
			} else if (errno == EAGAIN) {
				nerrs++;
				fwrite("G", 1, 1, stdout);
			} else {
				fprintf(stderr, "Write error: %s\n",
					strerror(errno));
				return -1;
			}
		} else {
			nsuccess++;
			fwrite(".", 1, 1, stdout);
		}
		iterations--;
		if (iterations) {
			column--;
			if (column == 0)
				column = 81 - printf("\n%d %d: ",
						     nsuccess, nerrs);
			fflush(stdout);
		}
	}
	printf("\n");

	return 0;
}

int coredump_with_threads(int nthreads, int iterations,
			  int (*op)(volatile bool *term, void *data),
			  void *data,
			  int (*do_coredump)(void))
{
	int i, rv, result;
	struct coredump_th_data *d;

	d = malloc(sizeof(*d));
	if (!d) {
		fprintf(stderr, "Unable to alloc coredump data");
		return -1;
	}
	memset(d, 0, sizeof(*d));
	d->thd = malloc(sizeof(*d->thd) * nthreads);
	if (!d->thd) {
		free(d);
		fprintf(stderr, "Unable to allocate per-thread data\n");
		return -1;
	}
	memset(d->thd, 0, sizeof(*d->thd) * nthreads);
	d->op = op;
	d->data = data;

	for (i = 0; i < nthreads; i++) {
		d->thd[i].d = d;
		rv = pthread_create(&d->thd[i].tid, NULL, th_run_op,
				    &d->thd[i]);
		if (rv) {
			fprintf(stderr, "pthread_create: %s\n", strerror(rv));
			break;
		}
	}

	if (rv) {
		result = -1;
	} else {
		sleep(2);
		iterate_coredumps(iterations, do_coredump);
	}

	d->terminate = true;
	for (i--; i >= 0; i--) {
		rv = pthread_join(d->thd[i].tid, NULL);
		if (rv) {
			result = -1;
			fprintf(stderr, "pthread_join failed: %s\n",
				strerror(rv));
		}
		if (d->thd[i].result) {
			result = -1;
			fprintf(stderr, "thread %d failed with: %s\n",
				i, strerror(d->thd[i].result));
		}
	}

	free(d->thd);
	free(d);

	return result;
}

int just_coredump(int nthreads, int iterations,
		  int (*op)(volatile bool *term, void *data), void *data,
		  int (*do_coredump)(void))
{
	return iterate_coredumps(iterations, do_coredump);
}

struct coredump_tests {
	const char *name;
	const char *descr;
	int (*func)(int nthreads, int iterations,
		    int (*op)(volatile bool *term, void *data), void *data,
		    int (*do_coredump)(void));
	int (*op)(volatile bool *term, void *data);
	int (*dump)(void);
} tests[] = {
	{
		"self",
		"A single-thread process takes a coredump of itself.",
		just_coredump, NULL, coredump_self
	},
	{
		"selfth",
		"A process takes a coredump of itself from a subthread.",
		just_coredump, NULL, coredump_from_th
	},
	{
		"proc",
		"Another process takes a coredump of a single-thread\n"
		"  process.",
		just_coredump, NULL, coredump_from_fork
	},
	{
		"spawner-self",
		"A thread takes a coredump of itself while multiple\n"
		"  threads spawn other threads.",
		coredump_with_threads, spawner, coredump_from_fork
	},
	{
		"spawner-selfth",
		"A sub-thread takes a coredump of itself while multiple\n"
		"  threads spawn other threads.",
		coredump_with_threads, spawner, coredump_from_fork
	},
	{
		"spawner-proc",
		"Another process takes a coredump of a process while\n"
		"  multiple threads spawn other threads.",
		coredump_with_threads, spawner, coredump_from_fork
	},
	{
		"io-self",
		"A thread takes a coredump of itself while multiple\n"
		"  threads do I/O.",
		coredump_with_threads, do_io, coredump_from_fork
	},
	{
		"io-selfth",
		"A sub-thread takes a coredump of itself while\n"
		"  multiple threads do I/O.",
		coredump_with_threads, do_io, coredump_from_fork
	},
	{
		"io-proc",
		"Another process takes a coredump of a process while\n"
		"  multiple threads do I/O.",
		coredump_with_threads, do_io, coredump_from_fork
	},
	{ NULL }
};

bool streq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

bool strstart(const char *a, const char *b, int *pos)
{
	bool rv;
	int len = strlen(b);

	rv = strncmp(a, b, len) == 0;
	if (rv)
		*pos = len;

	return rv;
}

int parse_int(int *val, int argc, char *argv[], int *i, int pos)
{
	char *nstr;
	char *end;

	if (pos >= 0 && argv[*i][pos] == '=') {
		/* Number is after the = in the arg. */
		nstr = &(argv[*i][pos + 1]);
	} else {
		if (*i + 1 >= argc) {
			fprintf(stderr, "No argument for parameter %s\n",
				argv[*i]);
			return -1;
		}
		nstr = argv[*i + 1];
		(*i)++;
	}

	if (strlen(nstr) == 0) {
		fprintf(stderr, "Empty argument for parameter %s\n", argv[*i]);
		return -1;
	}

	*val = strtol(nstr, &end, 0);
	if (*end != '\0') {
		fprintf(stderr, "Invalid argument for parameter %s\n",
			argv[*i]);
		return -1;
	}

	return 0;
}

int run_test(struct coredump_tests *t, int i, int nthreads, int iterations)
{
	printf("Running test %s: %s\n", t[i].name, t[i].descr);
	return t[i].func(nthreads, iterations, t[i].op, NULL, t[i].dump);
}

const char *helpstr = "\
Test the live application coredump feature\n\
   %s [-n <n>] [--num_threads=<n>] [-i] [--iterations=<n>] [-t]\n\
      [--take-coredump] [-h] ] [--help] [<testcase>]\n\
Parameters:\n\
  -n | --num_threads   - The number of threads to spawn for threaded tests\n\
  -i | --iterations    - The number of coredumps to take\n\
  -t | --take-coredump - Actually save a coredump.\n\
  -h | --help          - This help\n\
Normally the core limit is set to zero, use -t if you want to actually save\n\
a core.  If no testcase is specified, they are all run\n\
Testcases are:\n";

void help(const char *progname)
{
	int i;

	printf(helpstr, progname);
	for (i = 0; tests[i].name; i++)
		printf("  %s: %s\n", tests[i].name, tests[i].descr);
}

int main(int argc, char *argv[])
{
	int rv;
	int i = 1, parm;
	int nthreads = 20;
	int iterations = 1;

	for (; i < argc && argv[i][0] == '-'; i++) {
		int pos = -1;

		rv = 0;
		if (streq(argv[i], "-n") ||
		    strstart(argv[i], "--num-threads", &pos)) {
			rv = parse_int(&nthreads, argc, argv, &i, pos);
		} else if (streq(argv[i], "-i") ||
			   strstart(argv[i], "--iterations", &pos)) {
			rv = parse_int(&iterations, argc, argv, &i, pos);
		} else if (streq(argv[i], "-t") ||
			   streq(argv[i], "--take-coredump")) {
			dumpstr = "core_limit=unlimited\n";
		} else if (streq(argv[i], "-h") ||
			   streq(argv[i], "--help")) {
			help(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown parameter: %s\n", argv[i]);
			return -1;
		}
		if (rv)
			return -1;
	}

	parm = i;
	rv = 0;
	if (parm == argc) {
		for (i = 0; tests[i].name; i++) {
			rv = run_test(tests, i, nthreads, iterations);
			if (rv)
				break;
		}
	} else {
		for (; parm < argc; parm++) {
			for (i = 0; tests[i].name; i++) {
				if (streq(tests[i].name, argv[parm])) {
					rv = run_test(tests, i, nthreads,
						      iterations);
					break;
				}
			}
			if (!tests[i].name) {
				fprintf(stderr, "Unknown testcase: %s\n",
					argv[parm]);
				return -1;
			}
		}
	}

	return rv;
}

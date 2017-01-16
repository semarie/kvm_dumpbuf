/*
 * Copyright (c) 2017 Sebastien Marie <semarie@online.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/buf.h>

#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void);
static void dump_buf(u_long, struct buf *);
static void dump_bufhead(struct bufhead *);
static void print_verbose(const char *, ...)
	__attribute__((__format__(printf, 1, 2)));

int	 vflag = 0;
kvm_t	*kd;

int
main(int argc, char *argv[])
{
	char		 errstr[_POSIX2_LINE_MAX];
	char		*corefile = NULL, *execfile = NULL, *swapfile = NULL;
	int		 kvmflags = KVM_NO_FILES;
	int		 ch;
	struct nlist	 nl[2];
	struct bufhead	 bufhead;

	/* arguments parsing */
	while ((ch = getopt(argc, argv, "vM:N:W:")) != -1) {
		switch (ch) {
		case 'v':
			vflag = 1;
			break;
		case 'M':
			corefile = optarg;
			kvmflags = O_RDONLY;
			break;
		case 'N':
			execfile = optarg;
			kvmflags = O_RDONLY;
			break;
		case 'W':
			swapfile = optarg;
			kvmflags = O_RDONLY;
			break;
		default:
			usage();
		}
	}
	argc -= optind;

	if (argc != 0)
		usage();

	/* open kvm(3) interface */
	if ((kd = kvm_openfiles(execfile, corefile, swapfile, kvmflags, errstr))
	    == 0)
		errx(EXIT_FAILURE, "kvm_openfiles: %s", errstr);

	/* privdrop */
	if (pledge("stdio wpath cpath", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	/* initialise nl */
	memset(&nl, 0, sizeof(nl));
	nl[0].n_name = "bufhead";

	/* grab bufhead pointer value */
	if (kvm_nlist(kd, nl) == -1)
		err(EXIT_FAILURE, "kvm_nlist: kernel symbol table unreadable");

	/* read the value */
	print_verbose("bufhead=0x%lx\n", nl[0].n_value);
	if (kvm_read(kd, nl[0].n_value, &bufhead, sizeof(bufhead)) == -1)
		err(EXIT_FAILURE, "kvm_read: bufhead");

	/* dump it */
	dump_bufhead(&bufhead);

	return EXIT_SUCCESS;
}

static __dead void
usage()
{
	fprintf(stderr, "%s [-v] [-M core] [-N system] [-W swap]\n",
	    getprogname());
	exit(EXIT_FAILURE);
}

static void
print_verbose(const char *fmt, ...)
{
	va_list ap;

	if (! vflag)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
dump_bufhead(struct bufhead *bufhead)
{
	struct buf	 b;
	u_long		 b_addr;

	b_addr = (u_long)LIST_FIRST(bufhead);
	if (b_addr == 0)
		return;

	do {
		if (kvm_read(kd, b_addr, &b, sizeof(b)) == -1)
			err(EXIT_FAILURE, "dump_bufhead: kvm_read");

		dump_buf(b_addr, &b);

	} while ((b_addr = (u_long)LIST_NEXT(&b, b_list)) != 0);
}

static void
dump_buf(u_long b_addr, struct buf *b)
{
	size_t datasize = b->b_bufsize;
	char *data = NULL;
	char filename[PATH_MAX];
	int fd;
	off_t off;
	ssize_t n;
	
	print_verbose("buf=0x%lx\n", b_addr);

	/* alloc buffer for data */
	if ((data = malloc(datasize)) == NULL)
		err(EXIT_FAILURE, "dump_buf: malloc");

	/* read the data */
	if (kvm_read(kd, (u_long)b->b_data, data, datasize) == -1)
		err(EXIT_FAILURE, "dump_buf: kvm_read");

	/* generate the filename */
	(void)snprintf(filename, sizeof(filename),
	    "dump-%p-0x%lx", b->b_vp, b_addr);

	/* open the file */
	if ((fd = open(filename, O_WRONLY|O_CREAT|O_EXCL, 0600)) == -1)
		err(EXIT_FAILURE, "dump_buf: open: %s", filename);

	/* dump the value */
	for (off = 0; datasize - off > 0; off += n)
		if ((n = write(fd, data + off, datasize - off)) == -1)
			err(EXIT_FAILURE, "dump_buf: write: %s", filename);

	close(fd);
	free(data);
}

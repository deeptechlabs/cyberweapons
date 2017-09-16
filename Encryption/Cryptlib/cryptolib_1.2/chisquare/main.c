/*
 *	run battery of tests for randomness on characters of a file
 */
#include "bash.h"
#include <sys/types.h>
#include <sys/stat.h>

main(argc, argv)
int argc;
char *argv[];
{
	FILE *stream;
	struct stat sbuf;

	if (argc < 2) {
		fprintf(stderr, "Usage: chisquare filename (file should contain at least 1 Mbyte of random data)");
		exit(0);
	}
	stream = fopen(argv[1], "r");
	if (stream == 0) {
		perror(argv[1]);
		exit(1);
	}
	stat(argv[1], &sbuf);
	printf("%10d characters in file: %s\n\n", sbuf.st_size, argv[1]);
	frequency(stream);
	fflush(stdout);
	serial(stream);
	fflush(stdout);
	gap(stream, 100, 200);
	fflush(stdout);
	poker();
	fflush(stdout);
	coupon(stream);
	fflush(stdout);
	permute(stream);
	fflush(stdout);
	runs(stream);
	fflush(stdout);
	maximum(stream);
	fflush(stdout);
	mtuple(stream);
	fflush(stdout);
}

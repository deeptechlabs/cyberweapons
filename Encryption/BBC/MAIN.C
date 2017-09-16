#include <stdio.h>

extern int bbc_crypt(); /* defined in bbc.c */

FILE *my_fopen(file, type)
register char *file, *type;
{
  register FILE *fp;

  if ((fp = fopen(file, type)) != NULL) {
      return(fp);
  }
  fprintf(stderr, "Can't open '%s' for '%s'\n", file, type);
  exit(1);
}

void Usage()
{
    fprintf(stderr, "Usage:  bbc infile outfile (-d | -e)\n");
    exit(1);
}

main(argc, argv)
int argc;
char **argv;
{
    int encrypt_flag;
    long key1, key2, key3;
    FILE *infile, *outfile;

    if (argc != 4) {
	Usage();
    }
    if (!strcmp(argv[3], "-e")) {
	encrypt_flag = 1;
    } else if (!strcmp(argv[3], "-d")) {
	encrypt_flag = 0;
    } else {
	Usage();
    }
    infile = my_fopen(argv[1], "rb");
    outfile = my_fopen(argv[2], "wb");
    fprintf(stderr, "Enter 32-bit hex key1: ");
    scanf("%lx", &key1);
    fprintf(stderr, "Enter 32-bit hex key2: ");
    scanf("%lx", &key2);
    fprintf(stderr, "Enter 32-bit hex key3: ");
    scanf("%lx", &key3);
    bbc_crypt(infile, outfile, key1, key2, key3, encrypt_flag);
    exit(0);
}

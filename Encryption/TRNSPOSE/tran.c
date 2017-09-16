#include <stdio.h>

extern void set_rnd_seed();
extern int rnd();

#define BLOCKSIZE 8192

int  perm[BLOCKSIZE];
char buf[BLOCKSIZE];

FILE *my_fopen(file, type)
char *file, *type;
{
  FILE *fp;

  if (fp = fopen(file, type))
    return fp;
  (void) fprintf(stderr, "Can't open '%s'\n", file);
  exit(1);
}

main(argc, argv)
int argc;
char **argv;
{
  register int i, len;
  register FILE *infp, *outfp;
  int savlen, pos, key;
  char tmp;

  key   = (argc > 1) ? str2int(argv[1]) : 0;
  infp  = (argc > 2) ? my_fopen(argv[2], "r") : stdin;
  outfp = (argc > 3) ? my_fopen(argv[3], "w") : stdout;

  len = fread(buf, 1, BLOCKSIZE, infp);
  key += str2int(buf);
  set_rnd_seed(key);

  do {
    savlen = len;

    for (i = 0; i < len; i++)
      perm[i] = i;
    
#define swap(A,B)  tmp = A; A = B; B = tmp;

    while (len > 1)
      {
	pos = 1 + rnd() % (len - 1);
	swap( buf[perm[0]], buf[perm[pos]] );

	perm[0]   = perm[(pos == len - 2) ? len - 1 : len - 2];
	perm[pos] = perm[len - 1];
	len -= 2;
      }
    fwrite(buf, 1, savlen, outfp);
  } while (len = fread(buf, 1, BLOCKSIZE, infp));
}

/* Make an integer out of a string.  Do a poor job of it.
 * Note that since this function is called on a block of transposed
 * text and used to construct an "rng key", it mustn't be sensitive
 * to the position of characters  in `str'.
 */
int str2int(str)
char *str;
{
  int sum = 0;

  while (*str)
    sum += *str++;

  return sum;
}


#include <stdio.h>

/* This program tells if your processor is little- or big-endian */

int	errors;

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  endian();
  if (errors) {
    fprintf(stderr,"%d errors occurred\n");
  }
  return (errors != 0);
}

endian()

{
  unsigned long	x;
  char	*p;

  x = 0x01020304;

  p = (char*)&x;
  if (p[0] == 0x01 && p[1] == 0x02 && p[2] == 0x03 && p[3] == 0x04) {
    fputs("#define BIG_ENDIAN 1\n",stdout);
  } else if (p[0] == 0x04 && p[1] == 0x03 && p[2] == 0x02 && p[3] == 0x01) {
    fputs("#define LITTLE_ENDIAN 1\n",stdout);
  } else {
    fprintf(stderr,"Unkown endian\n");
    errors++;
  }
}

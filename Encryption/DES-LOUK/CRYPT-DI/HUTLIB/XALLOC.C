#include <stdio.h>
#include "hut-include.h"

char *
hut_alloc(n)

int	n;

{
  char	*r;
  if (!(r = malloc(n))) {
    fprintf(stderr,"hut_alloc: cannot alloc %d bytes\n",n);
    exit(1);
  }
  return r;
}

char *
hut_realloc(p,n)

char	*p;
int	n;

{
  char	*r;

  if (p) {
    r = realloc(p,n);
  } else {
    r = malloc(n);
  }
  if (!r) {
    fprintf(stderr,"hut_realloc: cannot realloc %d bytes\n",n);
    exit(1);
  }
  return r;
}

hut_free(p)

char	*p;

{
  return free(p);
}

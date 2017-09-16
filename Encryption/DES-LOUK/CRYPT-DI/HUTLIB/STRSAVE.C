#include <stdio.h>
#include "hut-include.h"
char *
hut_strsave(s)

char	*s;

{
  char	*r;

  r = malloc(strlen(s)+1);
  if (!r)
    return 0;
  strcpy(r,s);
  return r;
}

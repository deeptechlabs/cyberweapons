#include <stdio.h>
#include "hut-include.h"
#include <ctype.h>

char *
hut_next_field(np)

char	**np;

{
  char	*s = *np;
  char	*r;
  int	c;

  while ((c = *s) && isascii(c) && isspace(c))
    s++;
  if (!c)
    return 0;
  r = s;
  for(;;) {
    c = *s;
    if (!c) {
      *np = s;
      return r;
    }
    if (isascii(c) && isspace(c)) {
      *s = 0;
      *np = s+1;
      return r;
    }
    s++;
  }
}

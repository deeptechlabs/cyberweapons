#include <stdio.h>
#include "hut-include.h"
#include <ctype.h>

static int	ISIZE = 100;

hut_linebuf	hut_linebuf_z;

char *
hut_getline(f,buf)

FILE	*f;
hut_linebuf	*buf;

{
  int	l = 0;
  char	*r;
  char	*p = 0;
  char	*ep;
  int	c;
  int	e = 0;
  hut_linebuf	tmp;
  int	(*getcf)();

  if (!buf) {
    buf = &tmp;
    buf->data = 0;
    buf->len = 0;
    buf->getcf = 0;
  }
  getcf = buf->getcf;
  r = buf->data;
  l = buf->len;
  ep = r+l-3;
  for(;;) {
    if (getcf)
      c = getcf(f);
    else
      c = getc(f);
    if (c == EOF || c == '\n') {
      if (c == EOF && !p)
	return 0;
      e = 1;
    }
    if (p == 0)
      p = r;
    if (r == 0) {
      l = ISIZE;
      if (!(r = malloc(l)))
	return 0;
      buf->data = r;
      buf->len = l;
      p = r;
      ep = r+l-3;
    }
    if (p >= ep) {
      int	o;
      l += ISIZE;
      o = p - r;
      if (!(r = realloc(r,l)))
	return 0;
      buf->data = r;
      buf->len = l;
      p = r + o;
      ep = r+l-3;
    }
    if (e) {
      *p++ = 0;
      *p = c;
      buf->echar = c;
      return r;
    }
    *p++ = c;
  }
}

hut_free_linebuf(p)

hut_linebuf	*p;

{
  if (p->data)
    free(p->data);
}

#include <errno.h>
#include <stdio.h>
#include "hut-include.h"

extern int	sys_nerr;
extern char	*sys_errlist[];

char *
strerror(n)

int	n;

{
  static char	buf[30];

  if (n < 0 || n >= sys_nerr) {
    sprintf(buf,"Error %d",n);
    return buf;
  } else
    return sys_errlist[n];
}

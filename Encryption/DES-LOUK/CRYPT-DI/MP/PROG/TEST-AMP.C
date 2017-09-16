#include <hut-include.h>
#include "amp.h"
#include <stdio.h>

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  amp	*x1;
  amp	*x2;
  amp	*x3;
  amp	*x4;
  amp	*x5;
  amp	*t;
  int	i;
  int	z;
  char	*s;
  char	*s1;
  char	*s2;
  int	z2;
  int	m;
  amp	*mod;
  hut_linebuf	lb = hut_linebuf_z;

  if (!(s = hut_getline(stdin,&lb)))
    exit(1);
  mod = mp_htom(s);

  x5 = mp_itom(0);
  while (s = hut_getline(stdin,&lb)) {
    if (!(s1 = hut_next_field(&s)))
      continue;
    x1 = mp_htom(s1);
    if (!(s1 = hut_next_field(&s)))
      continue;
    x2 = mp_htom(s1);
    x3 = mp_pow_to(x5,x1,x2,mod);
    printf("%s %s %s\n",mp_mtoh(x1),mp_mtoh(x2),mp_mtoh(x5));
  }
  return 0;
}

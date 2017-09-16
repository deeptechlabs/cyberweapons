#include <hut-include.h>
#include "des.h"
#include <stdio.h>

extern char	*crypt();

int	nflag;
int	count;

typedef char	*(*fptr)();

extern char	*unix_crypt();
extern char	*crypt();

fptr	tcrypt = unix_crypt;

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  hut_linebuf	lb = hut_linebuf_z;
  char	*s,*s1,*s2,*key,*salt;
  int	i,c;

  while ((c = getopt(argc,argv,"nc:U")) != EOF) {
    switch (c) {
    case 'n':
      nflag++;
      break;
    case 'c':
      count = atoi(optarg);
      break;
    case 'U':
      tcrypt = crypt;
      break;
    }
  }

  while (s = hut_getline(stdin,&lb)) {
    if (!(salt = hut_next_field(&s)))
      continue;
    if (!(key = hut_next_field(&s)))
      continue;
    if (!nflag)
      s1 = crypt(key,salt);
    else
      s1 = "???";
    for(i = 0; i == 0 || i < count; i++)
      s2 = tcrypt(key,salt);

    printf("%-20s %-13s %s\n",key,s1,s2);
  }
  return 0;
}

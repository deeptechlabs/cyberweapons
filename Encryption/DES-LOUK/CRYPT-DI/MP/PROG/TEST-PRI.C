#include "amp.h"
#include <stdio.h>

/*
  This program test number for their primality. Numbers are given as standard input.
*/

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  amp	*mod;
  amp	*prime;
  int	m;
  int	is_prime;
  int	i;
  int	length;
  char	s[1024];
  int	j;

  m = atoi(argv[1]);
  for(;fgets(s,sizeof(s),stdin);) {
    prime = mp_xtom(s,16);
    for(i = 0, j = 0; i < 2; i++) {
      printf("Testing (%d) %s\n",i,mp_mtoh(prime));
      printf("             %s\n",mp_mtoa(prime));
      is_prime = mp_is_prime(prime,m);
      if (is_prime) {
	printf("%s is probably a prime (1/2^%d)\n",mp_mtoh(prime),m*2);
	j++;
      } else {
	printf("%s is not a prime.\n",mp_mtoh(prime));
      }
      if (j == 2)
	printf("Previous two are good for DH\n");
      mp_div_x_to(prime,prime,(mp_long)2,(mp_long*)0);
      printf("/2 %s\n",mp_mtoh(prime));
      fflush(stdout);
    }
  }
  return 0;
}

#include <hut-include.h>
#include "amp.h"
#include <stdio.h>

int	vflag;
int	ccount;

/*
  This program is used to find big primes. Usage is as:

  find-prime -s seedstring length probability

  length is the length of desired primes in bits. seedstring
  is used to initialize the random number generator
*/

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  amp	*mod;
  amp	*prime;
  amp	*prime2;
  amp	*p1,*p2;
  int	m;
  int	is_prime;
  int	i;
  int	length;
  char	s[1024];
  int	j;
  int	c;

  while ((c = getopt(argc,argv,"vs:c:")) != EOF) {
    switch (c) {
    case 'v':
      vflag++;
      break;
    case 's':
      mp_set_seed(optarg);
      break;
    case 'c':
      ccount = atoi(optarg);
      break;
    }
  }
  argv += optind;

  length = (*argv) ? atoi(*argv++) : 64;
  m = (*argv) ? atoi(*argv++) : 10;

  prime = new_amp();
  prime2 = new_amp();

  mod = mp_itom(1);
  for(i = 0; i < length; i++) {
    mp_mul_x_to(mod,mod,(mp_long)2);
  }
  
#if 0
  printf("Modulo is %s\n",mp_mtoh(mod));
#endif

  for(;;) {
    int	ok = 0;
    mp_random(prime,mod);
    prime->data[0] |= 03;
    
    for(; ok == 0;) {
      mp_div_x_to(prime2,prime,(mp_long)2,(mp_long*)0);
      if (vflag) {
	printf("Testing %s\n",mp_mtoh(prime));
	printf("        %s\n",mp_mtoa(prime));
      }
      is_prime = mp_is_prime(prime,m);
      if (is_prime) {
	printf("%s is probably a prime (1/2^%d)\n",mp_mtoh(prime),m*2);
	fflush(stdout);
	ok = 1;
	is_prime = mp_is_prime(prime2,m);
	if (is_prime) {
	  printf("%s is probably a prime (1/2^%d)\n",mp_mtoh(prime2),m*2);
	  printf("Previous two are good for DH scheme\n");
	  if (ccount) {
	    fflush(stdout);
	    is_prime = mp_is_prime(prime,ccount);
	    printf("%s %s\n",mp_mtoh(prime),is_prime ? "OK" : "*** is not a prime");
	    is_prime = mp_is_prime(prime2,ccount);
	    printf("%s %s\n",mp_mtoh(prime2),is_prime ? "OK" : "*** is not a prime");
	  }
	}
      } else {
	if (vflag) {
	  printf("%s is not a prime.\n",mp_mtoh(prime));
	}
      }
      fflush(stdout);
      if (!ok) {
	if (vflag) {
	  printf("Adding 4\n");
	}
	mp_add_x_to(prime,(mp_long)4);
      }
    }
  }
  return 0;
}

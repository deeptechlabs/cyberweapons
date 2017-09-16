#define MP_PRIVATE 1
#include "amp.h"
static const mp_int	mp_primes[] = {
#include "primes.h"
0,
};

int
mp_divisible(n,z)

amp	*n;
int	z;

{
  amp	*t;
  mp_long	rem;
  int		r;

  t = mp_copy(n);

  r = 0;
  for(;;) {
    if (t->len == 1 && t->data[0] == 0)
      break;
    mp_div_x_to(t,t,(mp_long)z,&rem);
    if (rem != 0)
      break;
    r++;
  }
  mp_free(t);
  return r;
}

mp_is_prime(mod,m)

amp	*mod;
int	m;

{
  int	w;
  amp	*x = 0;
  amp	*q = 0;
  amp	*y = 0;
  amp	*mod_1 = 0;
  mp_long	rem;
  int	i;
  int	j;
  int	k;
  int	not_prime = 0;
  const mp_int	*p;
  char	s[1024];

  for(p = mp_primes; *p; p++) {
    if (MP_EQ_SMALL(mod,*p))
      return 1;
    if (mp_divisible(mod,*p)) {
      return 0;
    }
  }

  if (m <= 0) return 1;

  mod_1 = mp_copy(mod);
  mp_sub_x_to(mod_1,(long)1);

  x = mp_itom(0);
  y = mp_itom(0);
  q = mp_copy(mod_1);

  k = 0;
  while (q->data[0] % 2 == 0) {
    mp_div_x_to(q,q,(mp_long)2,&rem);
    k++;
  }
  for(i = 0; i < m; i++) {
    for(;;) {
      mp_random(x,mod);
      if (x->len > 1 || x->data[0] > 1) {
	break;
      }
    }
    j = 0;
    mp_pow_to(y,x,q,mod);
    for(;;) {
      if ((j == 0 && y->len == 1 && y->data[0] == 1) ||
	  mp_cmp(y,mod_1) == 0) {
	goto cont0;
      }
      if (j > 0 && y->len == 1 && y->data[0] == 1) {
	not_prime = 1;
	goto end0;
      }
      j++;
      if (j < k) {
	mp_mul_to(q,y,y);
	mp_div_to(q,q,mod,y);
      } else {
	not_prime = 1;
	goto end0;
      }
    }
  cont0:;
  }
 end0:
  mp_free(mod_1);
  mp_free(x);
  mp_free(y);
  mp_free(q);
  return (!not_prime);
}

#include <stdio.h>
#define MP_PRIVATE 1
#include "amp.h"

int	mp_bl = 10;

#define DEFAULT_BUFLEN (mp_bl)

extern char	*malloc();
extern char	*realloc();

typedef struct amp0{
  amp		x;
  struct amp0	*next;
} amp0;

static amp0	*mp_freelist;

int		mp_n;

char *
mp_alloc(n)

int	n;

{
  char	*r;
  if (!(r = malloc(n))) {
    fprintf(stderr,"mp_alloc: cannot alloc %d bytes\n",n);
    exit(1);
  }
  return r;
}

char *
mp_realloc(p,n)

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
    fprintf(stderr,"mp_realloc: cannot realloc %d bytes\n",n);
    exit(1);
  }
  return r;
}

mp_free(p)

amp	*p;

{
  amp0	*pp;
  if (p && !p->not_malloced) {
    if (p->denom) {
      mp_free(p->denom);
      p->denom = 0;
    }
    pp = (amp0*)p;
    pp->next = mp_freelist;
    mp_freelist = pp;
    mp_n--;
  }
}

amp *
new_amp0(n)

int	n;

{
  amp	*r;

  if (n < DEFAULT_BUFLEN) n = DEFAULT_BUFLEN;
  if (mp_freelist) {
    r = &mp_freelist->x;
    mp_freelist = mp_freelist->next;
    MP_NEED(r,n);
  } else {
    r = (amp*)MP_NEW(amp0);
    r->data = MP_NEW_N(mp_int,n);
    r->buflen = n;
    r->d_str_len = 0;
    r->d_str = 0;
    r->denom = 0;
  }
  r->len = 1;
  r->data[0] = 0;
  r->d_str_valid = 0;
  r->sign = MP_POSITIVE;
  r->not_malloced = 0;
  mp_n++;
  return r;
}

amp *
mp_copy(a)

amp	*a;

{
  return mp_copy_to((amp*)0,a);
}

amp *
mp_copy_to(r,a)

amp	*r;
amp	*a;

{
  int	i;

  mp_remove_zeros(a);
  if (!r)
    r = new_amp_n(a->len);
  else {
    MP_TOUCH(r);
    MP_NEED(r,a->len);
  }
  r->len = a->len;
  for(i = 0; i < a->len; i++)
    r->data[i] = a->data[i];
  r->sign = a->sign;
  if (a->denom)
    r->denom = mp_copy_to(r->denom,a->denom);
  return r;
}

mp_need(p,n)

amp	*p;
int	n;

{
  if (n <= p->buflen)
    return;
  if (p->not_malloced) {
    fprintf(stderr,"mp_need: grow stack object to %d\n",n);
    exit(1);
  }
  p->buflen = n+10;
  p->data = (mp_int *)mp_realloc(p->data,p->buflen*sizeof(p->data[0]));
}

#include "des.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>

static des_u_char rev8bits[] = {
#include "eight.h"
};

int	gflag;
int	vflag;
int	tflag;
int	count = 1;

extern char	*optarg;
extern int	optind;

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  char	s[100];
  char	s_k[30];
  char	s_p[30];
  char	s_c[30];
  C_Block	b_key;
  C_Block	b_plain;
  C_Block	b_cipher;
  char	s_c1[30];
  char	s_p1[30];
  char	s_p2[30];
  C_Block	b_cipher1;
  C_Block	b_plain1;
  C_Block	b_plain2;
  C_Block	b_t;
  Key_schedule	sched;
  Key_schedule	sched2;
  int	err;
  int	c;
  int	e_c,e_p1,e_p2;
  int	i;
  
  while ((c = getopt(argc,argv,"vn:tg")) != EOF) {
    switch (c) {
    case 'v':
      vflag++;
      break;
    case 'n':
      count = atoi(optarg);
      break;
    case 't':
      tflag++;
      break;
    case 'g':
      gflag++;
      break;
    default:
      break;
    }
  }
  if (gflag) {
    tflag = 0;
    count = 1;
  }
  for(;;) {
    err = e_c = 0;
    rnd(&b_key);
    des_set_key_slow(&b_key,&sched);
    des_set_key(&b_key,&sched2);
    b_to_s(&b_key,s_k);
    if (b_cmp(&sched,&sched2)) {
      err++;
    }
    printf("%-2s Key: %s\n",err ? "" : "OK",s_k);
    if (err) {
      printf("Correct schedule:\n");
      pr_k(&sched);
      printf("Incorrect schedule:\n");
      pr_k(&sched2);
    }
  }
  return 0;
}

b_cmp(b1,b2)

Key_schedule	*b1;
Key_schedule	*b2;

{
  int	i;

  for(i = 0; i < 32; i++) {
    if (b1->data[i] != b2->data[i])
      return 1;
  }
  return 0;
}

b_to_s(b,s)

char	*s;
C_Block	*b;

{
  int	i;
  for(i = 0; i < 8; i++) {
    sprintf(&s[i*2],"%02x",rev8bits[b->data[i]]);
  }
}

s_to_b(s,b)

char	*s;
C_Block	*b;

{
  int	i;
  int	j;
  int	c;
  int	cc;

  for(i = 0; i < 8; i++) {
    cc = 0;
    for(j = 0; j < 2; j++) {
      c = s[i*2+j] & 0xff;
      if (c >= '0' && c <= '9')
	c -= '0';
      else if (c >= 'A' && c <= 'F')
	c -= ('A'-10);
      else if (c >= 'a' && c <= 'f')
	c -= ('a'-10);
      else
	return 1;
      cc = (cc << 4) + c;
    }
    b->data[i] = rev8bits[cc];
  }
  return 0;
}

extern long	random();

rnd(p)

C_Block	*p;

{
  *((des_u_long*)&p->data[0]) = random();
  *((des_u_long*)&p->data[4]) = random();
}

pr_k(p)

Key_schedule	*p;

{
  int	i;
  for(i = 0; i < 32; i += 4) {
    printf("0x%08x 0x%08x 0x%08x 0x%08x\n"
	   ,p->data[i+0],p->data[i+1],p->data[i+2],p->data[i+3]);
  }
}

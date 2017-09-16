#include "des.h"
#ifndef MSDOS
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <stdio.h>

static des_u_char rev8bits[] = {
#include "eight.h"
};

int	gflag;
int	vflag;
int	tflag;
int	sflag;
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
  int	err;
  int	c;
  int	e_c,e_p1,e_p2;
  int	i;
  int	mode = 0;
  C_Block	probe[16];
  
  while ((c = getopt(argc,argv,"vn:tgP")) != EOF) {
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
    case 'P':
      mode = DES_NOIPERM | DES_NOFPERM;
      break;
    case 's':
      sflag++;
      break;
    default:
      break;
    }
  }
  if (gflag) {
    tflag = 0;
    count = 1;
  }
  while(fgets(s,sizeof(s),stdin)) {
    e_c = e_p1 = e_p2 = err = 0;
    if (sscanf(s,"%s %s",s_k,s_p) != 2)
      break;
    s_to_b(s_k,&b_key);
    s_to_b(s_p,&b_plain);
    if (sflag)
      des_set_key_slow(&b_key,&sched);
    else
      des_set_key(&b_key,&sched);
    if (tflag)
      timing(0,count);
    des_ecb_encrypt_probe(&b_plain,&b_cipher1,&sched,DES_ENCRYPT | mode,&probe);
    des_ecb_encrypt(&b_cipher1,&b_plain2,&sched,DES_DECRYPT | mode);
    for(i = 3; i < count; i++)
      des_ecb_encrypt(&b_plain,&b_t,&sched,DES_ENCRYPT | mode);
    if (tflag)
      timing(1,count);
    b_to_s(&b_key,s_k);
    b_to_s(&b_plain,s_p);
    b_to_s(&b_cipher,s_c);
    b_to_s(&b_cipher1,s_c1);
    b_to_s(&b_plain1,s_p1);
    b_to_s(&b_plain2,s_p2);
    if (b_cmp(&b_cipher,&b_cipher1)) {
      err++;
      e_c++;
    }
    if (b_cmp(&b_plain,&b_plain1)) {
      err++;
      e_p1++;
    }
    if (b_cmp(&b_plain,&b_plain2)) {
      err++;
      e_p2++;
    }
    if (gflag) {
      printf("%s %s %s\n",s_k,s_p,s_c1);
    } else {
      int	i;
      printf("Key: %s  Pla: %s  Cip: %s",s_k,s_p,s_c1);
      printf("\n");
      for(i = 0; i < 16; i++) {
	char	ps[30];
	b_to_s(&probe[i],ps);
	printf("probe %02d %s\n",i,ps);
      }
      
      if (tflag)
	timing(2,count);
    }
  }
  if (tflag)
    timing(3,count);
  return 0;
}

b_cmp(b1,b2)

C_Block	*b1;
C_Block	*b2;

{
  int	i;

  for(i = 0; i < 8; i++) {
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

double
s_to_speed(s,count)

double	s;
int	count;

{
  return (8.0/1024.0)*(double)count/s;
}

timing(x,count)

int	x;
int	count;

{
#ifndef MSDOS
  static struct rusage	r[2];
  int		s,us;
  double	kbps;
  double	ss;
  static int	n;
  static double	total;
  static double	mint;
  static double	maxt;
  static int	cannot;

  switch (x) {
  case 0:
  case 1:
    getrusage(RUSAGE_SELF,&r[x]);
    cannot = 0;
    break;
  case 2:
    s = r[1].ru_utime.tv_sec - r[0].ru_utime.tv_sec;
    us = r[1].ru_utime.tv_usec - r[0].ru_utime.tv_usec;
    if (us < 0) {
      s--;
      us += 1000000;
    }
    ss = (double)s+(double)us/1000000.0;
    printf("%6d encryptions, utime: %8.2f   ",count,ss);
    if (ss > 0.01) {
      printf("%8.3f kbytes/s.",s_to_speed(ss,count));
    } else {
      printf("cannot calculate performance");
      cannot = 1;
    }
    printf("\n");
    if (n == 0) {
      mint = maxt = ss;
    } else {
      if (ss < mint)
	mint = ss;
      if (ss > maxt)
	maxt = ss;
    }
    total += ss;
    n++;
    break;
  case 3:
    if (n > 1 && !cannot) {
      printf("Average speed: %8.3f kbytes/s\n",s_to_speed(total/n,count));
      printf("Maximum speed: %8.3f kbytes/s\n",s_to_speed(mint,count));
      printf("Minimum speed: %8.3f kbytes/s\n",s_to_speed(maxt,count));
    }
  }
#endif
}

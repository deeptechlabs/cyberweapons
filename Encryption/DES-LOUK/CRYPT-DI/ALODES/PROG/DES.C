/* Copyright 1989 Antti Louko. All Rights Reserved.

/* This program encrypts and decrypts files with des algorithm. It can
   be used in three different modes: ecb, cbc or pcbc modes. -p selects
   pcbc mode, the default is cbc mode.

   Command syntax is: des [-e] [-d] [-h] [-k key] [-p] [infile [outfile]]

   des encrypts with -e flag and decrypt with -d flag.

 */

#include <stdio.h>
#include <hut-include.h>
#include "des.h"

#define myfopen fopen

#define BUFSIZE	8192

#define MODE_ECB 1
#define MODE_CBC 2
#define MODE_PCBC 3

extern int	optind;
extern char	*optarg;

int	eflag;
int	dflag;
int	hflag;
int	bflag;
int	xflag;
int	Xflag;
int	Sflag;
int	rflag;
int	c_count;
int	cbc = MODE_CBC;
int	do_output;

int	corr;

char	*getpass();

static char	*Xkey = "A-very-long-checksumkey";

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  char	*iname,*oname;
  FILE	*fin,*fout;
  int	c;
  char	*key = 0;
  Key_schedule	Key;
  int		mode;
  C_Block	bkey;
  int	ok;
  int	n;
  int	n2;
  char	buf[BUFSIZE+8];
  int	b;
  int	cnt;
  int	dmode;
  C_Block	ivec;

  ivec = des_zero_block;
  fin = stdin;
  fout = stdout;
  while ((c = getopt(argc,argv,"hedpxXSk:c:r")) != EOF) {
    switch (c) {
    case 'r':
      rflag++;
      break;
    case 'h':
      hflag++;
      break;
    case 'e':
      eflag++;
      do_output++;
      break;
    case 'd':
      dflag++;
      do_output++;
      break;
    case 'k':
      key = optarg;
      break;
    case 'c':
      c_count = atoi(optarg);
      break;
    case 'x':
      xflag++;
      break;
    case 'X':
      Xflag++;
      xflag++;
      break;
    case 'S':
      Sflag++;
      break;
    case 'p':
      cbc = MODE_PCBC;
      break;
    }
  }
  if (eflag + dflag + xflag!= 1) {
    fprintf(stderr,"Only one from -x, -X, -e and -d\n");
    exit(1);
  }
  if (dflag)
    mode = DES_DECRYPT;
  else
    mode = DES_ENCRYPT;
  if (xflag) {
    eflag = 1;
    cbc = MODE_PCBC;
    bflag = 0;
  }
  if (Sflag | rflag)
    mode |= DES_REVBITS;
  argv += optind;
  if (*argv) fin = myfopen(*argv++,"r");
  if (!fin) fprintf(stderr,"Cannot open input file\n");
  if (*argv) fout = myfopen(*argv++,"w");
  if (!fout) fprintf(stderr,"Cannot open output file\n");
  if (!key && xflag)
    key = Xkey;
  if (!key) {
    if (!(key = hut_read_password((hflag ?
				   "Enter hex key: " :
				   "Enter keyword: ")
				  ,1)))
      exit(1);
  }
  if (Sflag)
    des_sun_key(key,&bkey);
  else if (hflag) {
    if (des_hex_to_key(key,&bkey) == -1) {
      fprintf(stderr,"Invalid hex key\n");
      exit(1);
    }
  } else {
    string_to_key(key,&bkey);
  }
  if (key != Xkey) {
    while (*key) *key++ = 0;	/* Destroy key */
  }
  if (rflag)
    des_set_key_rev(&bkey,&Key);
  else
    des_set_key(&bkey,&Key);
  for(ok = 1; ok ;) {
    int	nread;
    if ((n = nread = fread(buf,1,BUFSIZE,fin)) < BUFSIZE) {
      ok = 0;
      b = n%8;
      if (!dflag) {
	n2 = ((n+8)&(~7)) - 1;
	buf[n2] = b;
	while (n < n2)
	  buf[n++] = 0;
	n = n2+1;
      } else {
	if (b != 0)
	  corr++;
      }
    }
    if (Xflag) {
      if ((n2 = fwrite(buf,1,nread,fout)) < nread) {
	fprintf(stderr,"Cannot write %d bytes; wrote %d bytes\n",nread,n2);
      }
    }
    cnt = (n+7)/8;
    c = c_count ? c_count : 1;
    for(; c > 0; c--) {
      switch (cbc) {
      case MODE_CBC:
	des_cbc_encrypt(buf,buf,cnt*8,&Key,&ivec,mode);
	break;
      case MODE_PCBC:
	des_pcbc_encrypt(buf,buf,cnt*8,&Key,&ivec,mode);
	break;
      }
    }
    if (dflag) {
      if (ok) {
	c = getc(fin);
	if (c == EOF) {
	  ok = 0;
	} else {
	  ungetc(c,fin);
	}
      }
      if (!ok) {
	b = buf[n-1];
	if (b > 7 || b < 0) {
	  corr++;
	  b = 7;
	} else
	  n -= 8-b;
      }
    }
    if (do_output) {
      if ((n2 = fwrite(buf,1,n,fout)) != n) {
	fprintf(stderr,"Cannot write %d bytes; wrote %d bytes\n",n,n2);
	exit(1);
      }
    }
  }
  if (corr) {
    fprintf(stderr,"Encrypted file is corrupted\n");
    exit(1);
  }
  if (xflag) {
    print_h(Xflag ? stderr : stdout,&ivec);
    fprintf(Xflag ? stderr : stdout,"\n");
  }
  return 0;
}

print_h(f,x)

FILE		*f;
C_Block		*x;

{
  int	i;

  for(i = 0; i < 8; i++)
    fprintf(f,"%02x",x->data[i]);
}

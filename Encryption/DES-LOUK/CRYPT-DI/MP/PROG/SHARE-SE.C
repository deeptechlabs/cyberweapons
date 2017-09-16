#include <hut-include.h>
#include "amp.h"
#include "des.h"
#include <stdio.h>

amp	*read_number();

amp	*modulo;
char	*default_modulo =
  "edcbaf322bfb0ce75dcdf9a806d9fd6768983c21aa4ed3f1b8ecfd8e20943fc7";

int	gflag;
int	cflag;

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  amp	*my_secret;
  amp	*my_public;
  amp	*his_public;
  amp	*the_secret;
  amp	*mp_three;
  int	i;
  int	z;
  char	*s;
  int	l;
  hut_linebuf	lb = hut_linebuf_z;
  int	c;
  char	*P_file = 0;
  char	*S_file = 0;

  modulo = mp_htom(default_modulo);
  mp_three = mp_atom("3");
  while ((c = getopt(argc,argv,"gcP:S:")) != EOF) {
    switch (c) {
    case 'g':
      gflag++;
      break;
    case 'c':
      cflag++;
      break;
    case 'P':
      P_file = optarg;
      break;
    case 'S':
      S_file = optarg;
      break;
    }
  }
  if (cflag) {
    his_public = read_number(P_file);
    my_secret = read_number(S_file);
    the_secret = mp_pow(his_public,my_secret,modulo);
    s = mp_mtoh(the_secret);
    if ((l = strlen(s)) < 32) {
      fprintf(stderr,"The secret is an invalid number\n");
      printf("1234567890abcde\n");
    } else {
      s += (l-16)/2;
      printf("%.16s\n",s);
    }
  } else if (gflag) {
    initilize_mp_random();
    my_secret = mp_random((amp*)0,modulo);
    my_public = mp_pow(mp_three,my_secret,modulo);
    write_number(S_file,my_secret);
    write_number(P_file,my_public);
  }
  return 0;
}

amp *
read_number(name)

char	*name;

{
  FILE	*f = 0;
  char	*s;
  hut_linebuf	lb = hut_linebuf_z;
  amp	*r;
  
  if (name) {
    if (!(f = fopen(name,"r"))) {
      fprintf(stderr,"Cannot open %s\n",name);
      exit(1);
    }
  }
  if (!(s = hut_getline(f ? f : stdin,&lb))) {
    fprintf(stderr,"Cannot read number\n");
    exit(1);
  }
  if (f) fclose(f);
  r = mp_htom(s);
  hut_free_linebuf(&lb);
  return r;
}

write_number(name,p)

char	*name;
amp	*p;

{
  FILE	*f = 0;
  
  if (name) {
    if (!(f = fopen(name,"w"))) {
      fprintf(stderr,"Cannot open %s\n",name);
      exit(1);
    }
  }
  fprintf(f ? f : stdout,"%s\n",mp_mtoh(p));
  if (f) fclose(f);
}

initilize_mp_random()

{
  C_Block	seed = des_zero_block;
  char	ibuf[1024];
  char	obuf[1024];
  int	n;

  DES_HASH_INIT();
  while ((n = fread(ibuf,1,sizeof(ibuf),stdin)) > 0) {
    des_cbc_encrypt(ibuf,obuf,n,&des_hash_key1,&seed,DES_ENCRYPT);
  }
  mp_set_seed(&seed);
}

#include <stdio.h>
#include <hut-include.h>
#include "des.h"

int	gflag;
int	cflag;

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  C_Block	x;
  char	str[20];
  int	c;

  while ((c = getopt(argc,argv,"")) != EOF) {
    switch (c) {
    }
  }
  initilize_random(&x);
  des_key_to_hex(&x,str);
  printf("%s\n",str);
  return 0;
}

initilize_random(seedp)

C_Block	*seedp;

{
  C_Block	seed;
  char	ibuf[1024];
  char	obuf[1024];
  int	n;

  seed = des_zero_block;
  DES_HASH_INIT();
  while ((n = fread(ibuf,1,sizeof(ibuf),stdin)) > 0) {
    des_cbc_encrypt(ibuf,obuf,n,&des_hash_key1,&seed,DES_ENCRYPT);
  }
  *seedp = seed;
}

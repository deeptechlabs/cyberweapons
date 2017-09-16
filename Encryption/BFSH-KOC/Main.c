/*
 * Author     :  Paul Kocher
 * E-mail     :  pck@netcom.com
 * Date       :  1997
 * Description:  C implementation of the Blowfish algorithm.
 */

#include <stdlib.h>

#include <assert.h>

#include <stdio.h>

#include "blowfish.h"



void main(void) {

  unsigned long L = 1, R = 2;

  BLOWFISH_CTX ctx;



  printf("%d\n", Blowfish_Test(&ctx));



  Blowfish_Init (&ctx, (unsigned char*)"TESTKEY", 7);

  Blowfish_Encrypt(&ctx, &L, &R);

  printf("%08lX %08lX\n", L, R);

  assert(L == 0xDF333FD2L && R == 0x30A71BB4L);

  Blowfish_Decrypt(&ctx, &L, &R);

  assert(L == 1 && R == 2);

}




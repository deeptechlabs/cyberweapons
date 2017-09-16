#ifndef _RC5_32_H_
#define _RC5_32_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  /* NOTE: for the substitution of the "real" .obj file to work, this
       structure needs to be defined correctly even when compiling the stub. */

  int encrypt;                                               /* encrypt flag */
} RC5_32_CBC_CTX;

int RC5_32_CBCInit PROTO_LIST 
  ((RC5_32_CBC_CTX *, unsigned char *, unsigned int, unsigned int,
    unsigned char *, int));
int RC5_32_CBCUpdate PROTO_LIST
  ((RC5_32_CBC_CTX *, unsigned char *, unsigned char *, unsigned int));
void RC5_32_CBCRestart PROTO_LIST ((RC5_32_CBC_CTX *));

#ifdef __cplusplus
}
#endif

#endif

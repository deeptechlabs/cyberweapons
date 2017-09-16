/* Header for RX2, an algorithm compatible with RC2.
   RC2 is a registered trademark of RSA Data Security, Inc.
 */

#ifndef _RX2_H_
#define _RX2_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  UINT2 keyBuffer[64];                                       /* expanded key */
  UINT2 iv[4];                                        /* initializing vector */
  UINT2 originalIV[4];                         /* for restarting the context */
  int encrypt;                                               /* encrypt flag */
} RX2_CBC_CTX;

int RX2_CBCInit PROTO_LIST 
  ((RX2_CBC_CTX *, unsigned char *, unsigned int, unsigned char *,
    unsigned int, int));
int RX2_CBCUpdate PROTO_LIST
  ((RX2_CBC_CTX *, unsigned char *, unsigned char *, unsigned int));
void RX2_CBCRestart PROTO_LIST ((RX2_CBC_CTX *));

#ifdef __cplusplus
}
#endif

#endif

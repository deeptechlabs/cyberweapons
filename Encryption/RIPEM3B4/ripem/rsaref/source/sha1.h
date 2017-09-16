/* This work is derived from the RSA Data Security, Inc. MD5 Message-
   Digest Algorithm, file md5.h.

   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD5 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.  
                                                                    
   No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
 */

#ifndef _SHA1_H_
#define _SHA1_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

/* SHA1 context. */
typedef struct {
  UINT4 state[5];                                    /* state H0 H1 H2 H3 H4 */
  UINT4 count[2];                 /* number of bits, modulo 2^64 (msb first) */
  unsigned char buffer[64];                                  /* input buffer */
} SHA1_CTX;

void SHA1Init PROTO_LIST ((SHA1_CTX *));
void SHA1Update PROTO_LIST
  ((SHA1_CTX *, unsigned char *, unsigned int));
void SHA1Final PROTO_LIST ((unsigned char *, SHA1_CTX *));

#ifdef __cplusplus
}
#endif

#endif

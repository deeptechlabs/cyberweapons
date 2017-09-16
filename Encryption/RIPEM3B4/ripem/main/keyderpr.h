/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

unsigned int PubKeyToDERLen P((R_RSA_PUBLIC_KEY *));
int PubKeyToDER P((R_RSA_PUBLIC_KEY *, unsigned char *, unsigned int *));
unsigned int PrivKeyToDERLen P((R_RSA_PRIVATE_KEY *));
void PrivKeyToDER P((R_RSA_PRIVATE_KEY *, unsigned char *, unsigned int *));
unsigned int EncryptedPrivKeyToDERLen P((unsigned int, unsigned int));
void EncryptedPrivKeyToDER
  P((unsigned char *, unsigned int, unsigned char *, unsigned int,
     unsigned char *, unsigned int *));
unsigned int der_len P((unsigned int));
void put_der_len P((unsigned char **, unsigned int));
unsigned int len_large_unsigned P((unsigned char *, unsigned int));
void put_der_large_unsigned
  P((unsigned char **, unsigned char *, unsigned int, unsigned int));
void put_der_data P((unsigned char **, unsigned char *, unsigned int));

#undef P

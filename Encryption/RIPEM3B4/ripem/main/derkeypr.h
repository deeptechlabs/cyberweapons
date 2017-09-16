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


/* derkey.c */
int DERToPubKey P((unsigned char *, R_RSA_PUBLIC_KEY *));
int DERToPrivKey P((unsigned char *, R_RSA_PRIVATE_KEY *));
int DERToEncryptedPrivKey
  P((unsigned char *, unsigned int, int *, unsigned char *, unsigned int *,
     unsigned char *, unsigned int *));
int gettaglen P((UINT2 *, unsigned int *, unsigned char **));
int getlargeunsigned P((unsigned char *, unsigned int, unsigned char **));
int DERCheckData P((unsigned char **, unsigned char *, unsigned int));
int DERToUTC P((unsigned char **, unsigned long *));

#undef P

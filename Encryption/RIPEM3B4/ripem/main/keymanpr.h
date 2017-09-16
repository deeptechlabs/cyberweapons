/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

/* keyman.c */
char *GetPrivateKey
  P((char *, TypKeySource *, R_RSA_PRIVATE_KEY *, unsigned char *,
     unsigned int, RIPEMInfo *));
char *GetNextUserRecordFromFile P((FILE *, unsigned int, char *, BOOL *));
char *WriteCert P((unsigned char *, RIPEMDatabase *));
char *WriteCRL P((unsigned char *, unsigned char *, RIPEMDatabase *));
int pbeWithMDAndDESWithCBC
  P((int, int, unsigned char *, unsigned int, unsigned char *, unsigned int,
     unsigned char *, unsigned int, unsigned int *));
void DESWithCBC
  P((int, unsigned char *, unsigned int, unsigned char *, unsigned char *));
void DumpPubKey P((R_RSA_PUBLIC_KEY *, FILE *));
void DumpPrivKey P((R_RSA_PRIVATE_KEY *, FILE *));
void DumpBigNum P((unsigned char *, int, FILE *));
char *GetLatestCRL
  P((RIPEMDatabase *, unsigned char **, unsigned char *, UINT4));
char *GetPreferencesByDigest
  P((RIPEMDatabase *, unsigned char **, unsigned char *, RIPEMInfo *));
char *WriteRIPEMPreferences
  P((unsigned char *, unsigned int, unsigned char *, RIPEMDatabase *,
     RIPEMInfo *));
char *RIPEMSealInit
  P ((RIPEMInfo *, R_ENVELOPE_CTX *, unsigned char *, unsigned char *,
      unsigned int *, RecipientKeyInfo *, unsigned int, int));
char *RIPEMUpdateFieldValue
  P ((BOOL *, char *, char *, char *, char *, unsigned char *, unsigned int,
      RIPEMInfo *));

#undef P

/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#ifdef __STDC__
# define  P(s) s
#else
# define P(s) ()
#endif

/* Forward declaration. */
struct CertificateStruct;

void CheckSelfSignedCert
  P((int *, struct CertificateStruct *, unsigned char *, unsigned int));
char *InsertCerts P((TypList *, RIPEMInfo *, RIPEMDatabase *));
char *InsertUniqueCert P((unsigned char *, RIPEMInfo *, RIPEMDatabase *));
char *VerifyAndInsertCRL P((unsigned char *, RIPEMInfo *, RIPEMDatabase *));
void ComputeIssuerSerialAlias
  P((unsigned char *, DistinguishedNameStruct *, unsigned char *,
     unsigned int));
char *RIPEMLoadPreferences P((RIPEMInfo *, RIPEMDatabase *));
BOOL IsIssuerSerialAlias P((RIPEMInfo *, unsigned char *));
char *AddUserIssuerCerts P((RIPEMInfo *, TypList *, RIPEMDatabase *));
char *GetLoggedInLatestCRL
  P((unsigned char **, int *, RIPEMInfo *, RIPEMDatabase *));

#undef P

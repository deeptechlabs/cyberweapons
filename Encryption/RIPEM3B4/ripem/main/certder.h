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

/* Define the max that an encoding can expand by wrapping a sequence
     with an algorithm identifier and a signature.
   4 is the beginning SEQ. 15 is the size of the md2WithRSA algorithm ID.
     3 + 1 is the beginning of the bit string for the signature.
 */
#define MAX_UNSIGNED_TO_SIGNED_DELTA (4 + 15 + 3 + 1 + MAX_SIGNATURE_LEN)

typedef struct CRLStruct {
  int digestAlgorithm;
  DistinguishedNameStruct issuer;
  unsigned long lastUpdate;                            /* seconds since 1970 */
  unsigned long nextUpdate;                            /* seconds since 1970 */
  /* Note: crlEntries are in CRLFieldPointers */
  unsigned char signature[MAX_SIGNATURE_LEN];
  int signatureLen;
} CRLStruct;

typedef struct {
  unsigned char *innerDER;
  unsigned int innerDERLen;
  unsigned char *crlEntriesDER;                   /* NULL if entries omitted */
} CRLFieldPointers;

int DERToDistinguishedName
  P((unsigned char **, DistinguishedNameStruct *));
unsigned int len_certificate P((CertificateStruct *, int));
void CertificateToDer
  P((CertificateStruct *, unsigned char *, unsigned int *));
unsigned int len_crl
  P((CRLStruct *, unsigned char *, unsigned char *, unsigned int));
void CRLToDer
  P((CRLStruct *, unsigned char *, unsigned char *, unsigned int, UINT4, 
     unsigned char *, unsigned int *));
void DerUnsignedToDerSigned
  P((unsigned char *, unsigned int *, unsigned char *, unsigned int, int,
     BOOL));
unsigned int len_distinguishedname P((DistinguishedNameStruct *));
void DistinguishedNameToDER P((DistinguishedNameStruct *, unsigned char **));
int DERToCRL P((unsigned char *, CRLStruct *, CRLFieldPointers *));
int FindCRLEntry P((BOOL *, unsigned char *, unsigned char *, unsigned int));
char *DERToPreferences
  P((unsigned char *, RIPEMInfo *, unsigned char *, unsigned char **,
     unsigned int *));
unsigned int len_preferences P((RIPEMInfo *));
void PreferencesToDer P((RIPEMInfo *, unsigned char *, unsigned int *));
void RIPEMResetPreferences P((RIPEMInfo *));
char *UpdateChainLensAllowed
  P((RIPEMInfo *, unsigned char *, unsigned int));

#undef P

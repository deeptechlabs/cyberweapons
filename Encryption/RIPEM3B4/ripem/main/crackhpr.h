/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

typedef struct TypMsgInfo {
  enum enum_ids proc_type;    /* Processing type (ENCRYPTED, MIC-ONLY, etc.) */
  unsigned char iv[8];                         /* DES Initialization Vector. */
  int da;                                   /* Digest algorithm (DA_ symbol) */
  unsigned char *mic;                                       /* Encrypted MIC */
  unsigned int mic_len;                              /* # of bytes in above. */
  unsigned char *msg_key;                           /* Encrypted message key */
  unsigned int msg_key_len;                          /* # of bytes in above. */
  char *orig_name;                /* Originator's name, or NULL if not found */
  R_RSA_PUBLIC_KEY orig_pub_key;                     /* Originator's pub key */
  BOOL  got_orig_pub_key;                 /* TRUE if header has Orig pub key */
  int ea;
  unsigned char *originatorCert;                           /* alloced buffer */
  unsigned char *crlToInsert;                              /* alloced buffer */

  /* These variables keep track of the state between calls to
       DoHeaderLine. */
  BOOL foundBeginBoundary, doingHeader, inEmailHeaders, thisUser;
  BufferStream extendedLine;
} TypMsgInfo;

#ifdef __STDC__
# define  P(s) s
#else
# define P(s) ()
#endif

void TypMsgInfoConstructor P((TypMsgInfo *));
void TypMsgInfoDestructor P((TypMsgInfo *));
char *ProcessHeaderLine
  P((RIPEMInfo *, TypMsgInfo *, BOOL *, char *, BOOL, TypList *,
     RIPEMDatabase *));

#undef P

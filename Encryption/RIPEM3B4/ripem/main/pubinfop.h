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


/* pubinfo.c */
int ReadUserRecord P((FILE *, char *, int, int *));
int ReadUserRecord P((FILE *, char *, int, int *));
char *FindUserInRecord P((BOOL *, char *, char *));
BOOL PosFileLine P((FILE *, char *, FILE *));
BOOL GetFileLine P((FILE *, char *, char *, int));
int ExtractValue P((char *, char *, unsigned int));
int CrackKeyField P((char *, char *, char *, int));
int GetPubInfoFromFile P((FILE *, char *, unsigned int, unsigned int *));
int NextLineInBuf P((char **));
BOOL ExtractPublicKeyLines P((char *, char *, int));

#undef P

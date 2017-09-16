/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/* "Cannot allocate memory" error string to be used throughout command-line
   applications. */
extern char *ERROR_MALLOC;

#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

#define BASE64_CHUNK_SIZE 48
typedef struct {
  unsigned char buffer[BASE64_CHUNK_SIZE];
  unsigned int bufferLen;
} Base64Encoder;

char *EstablishRIPEMHomeDir P((char **, RIPEMInfo *));
void WritePrintableName P((FILE *, DistinguishedNameStruct *));
char *StrCopyAlloc P((char **, char *));
char *StrConcatRealloc P((char **, char *));
int matchn P((char *str , char *pattern , int nchars ));
int GetRandomBytes P((unsigned char *, int, RIPEMInfo *));
void CopyRandomBytes
  P((void *, int, unsigned char *, int *, int *, char *, RIPEMInfo *));
void ReportCPUTime P((char *, RIPEMInfo *));
void GetUserInput
  P((unsigned char userbytes [], int *num_userbytes ,
     unsigned char timebytes [], int *num_timebytes , int echo));
int  GetUserName P((char **name ));
unsigned int GetPasswordFromUser
  P((char *prompt , BOOL verify , unsigned char *password ,
     unsigned int maxchars ));
void GetUserAddress P((char **address ));
void GetUserHome P((char **home ));
void ExpandFilename P((char **fileName));
void Base64EncoderConstructor P((Base64Encoder *));
void Base64EncoderDestructor P((Base64Encoder *));
void Base64EncoderWriteInit P((Base64Encoder *));
void Base64EncoderWriteUpdate
  P((Base64Encoder *, unsigned char *, unsigned int, FILE *));
void Base64EncoderWriteFinal P((Base64Encoder *, FILE *));
BOOL CaseIgnoreEqual P((char *, char *));
void GetDateAndTimeFromTime P((char *, UINT4));
#ifndef MACTC	/* rwo */
BOOL GetEnvFileName P((char *envName , char *defName , char **fileName ));
BOOL GetEnvAlloc P((char *envName , char **target ));
#else
BOOL GetEnvFileName P((short envName , char *defName , char **fileName ));
BOOL GetEnvAlloc P((short envName , char **target ));
#endif
#undef P

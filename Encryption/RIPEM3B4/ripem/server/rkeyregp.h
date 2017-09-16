#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* rkeyreg.c */
int main P((int argc , char *argv []));
char *ScanDir P((DIR *dirp , int action ));
char *ProcessAddFile P((char *fileName , int replyToUser ));
char *ProcessChangeFile P((char *fileName , int replyToUser , int action ));
char *OpenKeyDatabase P((GDBM_FILE *dbf ));
void CloseKeyDatabase P((GDBM_FILE dbf ));
void SigHandler P((int signo ));
int ReportViaEmail P((char *emailAddr , TypList *userList , int nKeys ));
int LogKeyFile P((FILE *instream , int action ));
int GetPidToNotify P((void ));

#undef P

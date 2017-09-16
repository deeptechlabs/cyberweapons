#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* db2flat.c */
int main P((int argc , char *argv []));
int DumpIt P((GDBM_FILE dbf , FILE *outStream ));
void WriteKeyRec P((datum key , datum dat , FILE *outStream ));

#undef P

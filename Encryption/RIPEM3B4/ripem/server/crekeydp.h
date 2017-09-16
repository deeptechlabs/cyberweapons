#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* crekeydb.c */
int main P((int argc , char *argv []));
int FillDatabase P((FILE *instream , GDBM_FILE dbf , int n_items ));
int CrackName P((char *bptr , char *name , unsigned int maxLen ));
int GetPubInfoFromFile P((FILE *stream , char *buf , unsigned int bufLen , unsigned int *returnedLen ));
int NextLineInBuf P((char **buf ));

#undef P

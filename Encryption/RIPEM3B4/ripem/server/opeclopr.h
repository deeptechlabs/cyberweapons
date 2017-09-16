#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* opeclo.c */
char *OpenKeyDatabase P((char *DBName , int forWrite , GDBM_FILE *dbf ));
void CloseKeyDatabase P((GDBM_FILE dbf ));

#undef P

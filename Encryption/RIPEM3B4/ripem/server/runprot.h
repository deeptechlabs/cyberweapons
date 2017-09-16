#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* run.c */
int RunAndGetOutput P((char *prog , char *argv [], int *retval , char **retbuf , int *bufsize , char **errbuf , int *errbufsize ));

#undef P

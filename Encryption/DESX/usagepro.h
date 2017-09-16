#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

void usage P((char *line1 , char **msg ));

#undef P
#undef P

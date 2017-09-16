#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

int getopt P((int argc , char **argv , char *opts ));

#undef P
#undef P

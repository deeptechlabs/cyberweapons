#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* getreta.c */
char *GetReturnAddress P((FILE *instream ));

#undef P

#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* uucode.c */
int uuencode P((unsigned char *bufin , unsigned int nbytes , unsigned char *bufcoded ));
int uudecode P((unsigned char *bufcoded , unsigned char *bufplain ));

#undef P

#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* startnetmail.c */
int StartNetMail P((char *eMailAddr , int *fd ));

#undef P

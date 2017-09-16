#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* sendnetmail.c */
int SendNetMail P((char *eMailAddr , TypList *lineList ));

#undef P

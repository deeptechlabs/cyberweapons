#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* givepubs.c */
int main P((int argc , char *argv []));

#undef P

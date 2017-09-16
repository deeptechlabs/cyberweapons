#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* newdes2.c */
unsigned int newdes_buf P((unsigned char *buf , unsigned int block_length ));
void newdes_block P((unsigned char *block ));
void newdes_set_key_encipher P((unsigned char *key ));
void newdes_set_key_decipher P((unsigned char *key ));

#undef P

/* des3.h 95/09/14 20:47:47 EDT */

#define DES3    /* include support for triple-length keys?   */
#define PORT    /* 68K: are odd-alligned 'unsigned long' OK? */

extern void des2key( unsigned char hexkey[16], short mode,
                        unsigned long keyout[96] );
#ifdef DES3
extern void des3key( unsigned char hexkey[24], short mode,
                        unsigned long keyout[96] );
#endif

#ifdef PORT
extern void des3( unsigned char inblock[8], unsigned char outblock[8],
                        unsigned long keysched[96] );
#else
extern void des3( unsigned long inblock[2], unsigned long outblock[2],
                        unsigned long keysched[96] );
#endif

#define EN0    0        /* MODE == encrypt */
#define DE1    1        /* MODE == decrypt */

/* end des3.h */

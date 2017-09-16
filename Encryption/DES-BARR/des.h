#define DES_BLOCKSIZE	8
#define MAXKEYLEN 	DES_BLOCKSIZE

#ifdef mips
typedef char *keyType;		/* mips won't recognize keyType x for void * */
#else
typedef void *keyType;
#endif

#ifndef __STDC__
extern void desMakeKey();
extern void des();
extern int  desInBlockSize(); 
extern int  desOutBlockSize(); 

/* From descfb.c */
extern unsigned desCFB();
extern void	desXor();
/* From deskey.c */
extern void 	desKey();
extern void	desStrMAC();
#else
extern void desMakeKey(keyType *key, char *keystr, unsigned size, int decrFlag);
extern void des(char *dst, char *src, keyType key);
extern int  desInBlockSize(keyType); 
extern int  desOutBlockSize(keyType); 

/* From descfb.c */
extern unsigned desCFB(
   char *dst, char *src, unsigned size, 
   char *iv, unsigned ivsize, keyType key, int decr
);
extern void desXor(char *dst, char *src0, char *src1, unsigned size);

/* from deskey.c */
extern void desKey(char *keybits, char *str, int pad);
extern void 
   desStrMac(char *mac, char *src, unsigned len, char pad, keyType key);
#endif

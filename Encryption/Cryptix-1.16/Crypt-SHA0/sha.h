#ifndef SHA_H
#define SHA_H

/* NIST Secure Hash Algorithm */
/* heavily modified from Peter C. Gutmann's implementation */

/* Useful defines & typedefs */

#define SHA_BLOCKSIZE		64
#define SHA_DIGESTSIZE		20

typedef struct {
    unsigned long digest[5];		/* message digest */
    unsigned long count_lo, count_hi;	/* 64-bit bit count */
    unsigned long data[16];		/* SHA data buffer */
    int local;			/* unprocessed amount in data */
} SHA_INFO;

void sha_init(SHA_INFO *);
void sha_update(SHA_INFO *, unsigned char *, int);
void sha_final(SHA_INFO *);

#endif /* SHA_H */

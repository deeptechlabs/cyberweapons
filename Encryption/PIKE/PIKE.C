From uucp Mon Mar 20 08:13 CST 1995
Received: from Mailbox by chinet.chinet.com; Mon, 20 Mar 95 08:13 CST
Received: by mailbox.mcs.com (/\==/\ Smail3.1.28.1 #28.5)
	id <m0rqhn5-000jopC@mailbox.mcs.com>; Mon, 20 Mar 95 07:46 CST
Received: by mercury.mcs.com (/\==/\ Smail3.1.28.1 #28.5)
	id <m0rqhn4-000Bk6C@mercury.mcs.com>; Mon, 20 Mar 95 07:46 CST
Received: from delphi.com by delphi.com (PMDF V4.3-9 #7804)
 id <01HOCPV5EXMO938PFK@delphi.com>; Mon, 20 Mar 1995 08:46:35 -0500 (EST)
Date: Mon, 20 Mar 1995 08:46:35 -0500 (EST)
From: JMKELSEY@delphi.com
Subject: pike implementation
To: schneier@chinet.com
Message-id: <01HOCPV5F79U938PFK@delphi.com>
X-VMS-To: INTERNET"schneier@chinet.com"
MIME-version: 1.0
Content-Length: 20484
Content-Type: TEXT/PLAIN; CHARSET=US-ASCII
Content-transfer-encoding: 7BIT
Status: O

#include <stdio.h>
#include "SHSIMP.H"

/* --------------------------------------------------------------------
** Pike, a stream cipher proposed at the Leuven Algorithms Workshop by
** Ross Anderson, Dec 1994.
**
** General scheme of cipher:  Use three lagged fibonacci generators to generate
** a keystream.  The three generators are clocked using a variant of the
** scheme A5 uses--take the carry bit from each of the generators, and clock
** the generators whose clock bit is the same as the majority of the carry bits.
** The outputs of the generators are XORed together.
** See "On Fibonacci Keystream Generators," by Ross Anderson, for specific
** details.
**
** Implemented by John Kelsey, jmkelsey@delphi.com, Dec 1994.
** Ported from C++ to C by John Kelsey, March 1995, for inclusion in
** Schneier's _Applied Cryptography_.
**
** Notes:
**
** 1.   The key scheduling is mine.  It's relatively slow, on the theory
**      that key scheduling is a rare event.  PIKE looks like it
**      wouldn't deal well with a bad key scheduling scheme, so I've
**      used multiple applications of a hash function to make every bit
**      of the expanded key (ie the initial LFG state) dependent on
**      every bit of the key, and the key length, in a complicated way.
**      The key is variable-length, from 0 to 255 bytes.  There doesn't
**      seem to be a way to test for weak keys except by doing the key
**      expansion, and looking for exploitable patterns in the initial
**      state of the lfgs.  I don't see any likely patterns that would
**      cause weaknesses, for what it's worth.  The hash function is
**      currently SHA, but there's no reason why another one can't be
**      used.  This key scheduling scheme isn't really suitable for
**      applications that need to change encryption keys often, but
**      the same is true of PIKE, which requires over 150 32-bit words
**      of state.
**
** 2.   PIKE isn't all that fast in a C implementation, because of the
**      need to get access to the carry bit.  A 32-bit assembly-language
**      implementation of the lfg routines would be a good idea for
**      high-speed applications.
**
** 3.   This isn't exactly a speed-optimized implementation in any event.
**
-------------------------------------------------------------------- */

/* ----------------------------------------------------------------- */
/* Type and struct definitions appear here. */
/* ----------------------------------------------------------------- */


/* Generally useful typedefs: */
typedef unsigned char u1;
typedef unsigned int u2;
typedef unsigned long u4;

/* LFG = a lagged Fibonacci generator.  This is a fast way to generate */
/* pseudorandom 32-bit integers with reasonably good statistics and a */
/* long cycle. */

typedef struct {
	int 	len, tap, pos, tpos, carry;
	u4      *reg,curr;
} lfg;

/* ---------------------- SHS IMPLEMENTATION FOR KEY SCHED -------------- */
/* NIST proposed Secure Hash Standard.

   Written 2 September 1992, Peter C. Gutmann.
   This implementation placed in the public domain.

   Comments to pgut1@cs.aukuni.ac.nz */

/* Useful defines/typedefs */

typedef unsigned char   BYTE;
typedef unsigned long   LONG;

/* The SHS block size and message digest sizes, in bytes */

#define SHS_BLOCKSIZE   64
#define SHS_DIGESTSIZE  20

/* The structure for storing SHS info */

typedef struct {
             LONG digest[ 5 ];            /* Message digest */
             LONG countLo, countHi;       /* 64-bit bit count */
             LONG data[ 16 ];             /* SHS data buffer */
             } SHS_INFO;

/* Whether the machine is little-endian or not */

#define LITTLE_ENDIAN

/* --------------------------------- SHS.C ------------------------------- */

/* NIST proposed Secure Hash Standard.

   Written 2 September 1992, Peter C. Gutmann.
   This implementation placed in the public domain.

   Comments to pgut1@cs.aukuni.ac.nz */

#include <string.h>

/* The SHS f()-functions */

#define f1(x,y,z)   ( ( x & y ) | ( ~x & z ) )              /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                           /* Rounds 20-39 */
#define f3(x,y,z)   ( ( x & y ) | ( x & z ) | ( y & z ) )   /* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )                           /* Rounds 60-79 */

/* The SHS Mysterious Constants */

#define K1  0x5A827999L     /* Rounds  0-19 */
#define K2  0x6ED9EBA1L     /* Rounds 20-39 */
#define K3  0x8F1BBCDCL     /* Rounds 40-59 */
#define K4  0xCA62C1D6L     /* Rounds 60-79 */

/* SHS initial values */

#define h0init  0x67452301L
#define h1init  0xEFCDAB89L
#define h2init  0x98BADCFEL
#define h3init  0x10325476L
#define h4init  0xC3D2E1F0L

/* 32-bit rotate - kludged with shifts */

#define S(n,X)  ( ( X << n ) | ( X >> ( 32 - n ) ) )

/* The initial expanding function */

#define expand(count)   W[ count ] = W[ count - 3 ] ^ W[ count - 8 ] ^ W[ count - 14 ] ^ W[ count - 16 ]

/* The four SHS sub-rounds */

#define subRound1(count)    \
    { \
    temp = S( 5, A ) + f1( B, C, D ) + E + W[ count ] + K1; \
    E = D; \
    D = C; \
    C = S( 30, B ); \
    B = A; \
    A = temp; \
    }

#define subRound2(count)    \
    { \
    temp = S( 5, A ) + f2( B, C, D ) + E + W[ count ] + K2; \
    E = D; \
    D = C; \
    C = S( 30, B ); \
    B = A; \
    A = temp; \
    }

#define subRound3(count)    \
    { \
    temp = S( 5, A ) + f3( B, C, D ) + E + W[ count ] + K3; \
    E = D; \
    D = C; \
    C = S( 30, B ); \
    B = A; \
    A = temp; \
    }

#define subRound4(count)    \
    { \
    temp = S( 5, A ) + f4( B, C, D ) + E + W[ count ] + K4; \
    E = D; \
    D = C; \
    C = S( 30, B ); \
    B = A; \
    A = temp; \
    }

/* The two buffers of 5 32-bit words */

LONG h0, h1, h2, h3, h4;
LONG A, B, C, D, E;


/* Initialize the SHS values */

void shsInit( shsInfo )
   SHS_INFO *shsInfo;
    {
    /* Set the h-vars to their initial values */
    shsInfo->digest[ 0 ] = h0init;
    shsInfo->digest[ 1 ] = h1init;
    shsInfo->digest[ 2 ] = h2init;
    shsInfo->digest[ 3 ] = h3init;
    shsInfo->digest[ 4 ] = h4init;

    /* Initialise bit count */
    shsInfo->countLo = shsInfo->countHi = 0L;
    }

/* Perform the SHS transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers - it may be necessary to split it into
   sections, eg based on the four subrounds */

void shsTransform( shsInfo )
  SHS_INFO *shsInfo;
    {
    LONG W[ 80 ], temp;
    int i;

    /* Step A.  Copy the data buffer into the local work buffer */
    for( i = 0; i < 16; i++ )
	W[ i ] = shsInfo->data[ i ];

    /* Step B.  Expand the 16 words into 64 temporary data words */
    expand( 16 ); expand( 17 ); expand( 18 ); expand( 19 ); expand( 20 );
    expand( 21 ); expand( 22 ); expand( 23 ); expand( 24 ); expand( 25 );
    expand( 26 ); expand( 27 ); expand( 28 ); expand( 29 ); expand( 30 );
    expand( 31 ); expand( 32 ); expand( 33 ); expand( 34 ); expand( 35 );
    expand( 36 ); expand( 37 ); expand( 38 ); expand( 39 ); expand( 40 );
    expand( 41 ); expand( 42 ); expand( 43 ); expand( 44 ); expand( 45 );
    expand( 46 ); expand( 47 ); expand( 48 ); expand( 49 ); expand( 50 );
    expand( 51 ); expand( 52 ); expand( 53 ); expand( 54 ); expand( 55 );
    expand( 56 ); expand( 57 ); expand( 58 ); expand( 59 ); expand( 60 );
    expand( 61 ); expand( 62 ); expand( 63 ); expand( 64 ); expand( 65 );
    expand( 66 ); expand( 67 ); expand( 68 ); expand( 69 ); expand( 70 );
    expand( 71 ); expand( 72 ); expand( 73 ); expand( 74 ); expand( 75 );
    expand( 76 ); expand( 77 ); expand( 78 ); expand( 79 );

    /* Step C.  Set up first buffer */
    A = shsInfo->digest[ 0 ];
    B = shsInfo->digest[ 1 ];
    C = shsInfo->digest[ 2 ];
    D = shsInfo->digest[ 3 ];
    E = shsInfo->digest[ 4 ];

    /* Step D.  Serious mangling, divided into four sub-rounds */
    subRound1( 0 ); subRound1( 1 ); subRound1( 2 ); subRound1( 3 );
    subRound1( 4 ); subRound1( 5 ); subRound1( 6 ); subRound1( 7 );
    subRound1( 8 ); subRound1( 9 ); subRound1( 10 ); subRound1( 11 );
    subRound1( 12 ); subRound1( 13 ); subRound1( 14 ); subRound1( 15 );
    subRound1( 16 ); subRound1( 17 ); subRound1( 18 ); subRound1( 19 );
    subRound2( 20 ); subRound2( 21 ); subRound2( 22 ); subRound2( 23 );
    subRound2( 24 ); subRound2( 25 ); subRound2( 26 ); subRound2( 27 );
    subRound2( 28 ); subRound2( 29 ); subRound2( 30 ); subRound2( 31 );
    subRound2( 32 ); subRound2( 33 ); subRound2( 34 ); subRound2( 35 );
    subRound2( 36 ); subRound2( 37 ); subRound2( 38 ); subRound2( 39 );
    subRound3( 40 ); subRound3( 41 ); subRound3( 42 ); subRound3( 43 );
    subRound3( 44 ); subRound3( 45 ); subRound3( 46 ); subRound3( 47 );
    subRound3( 48 ); subRound3( 49 ); subRound3( 50 ); subRound3( 51 );
    subRound3( 52 ); subRound3( 53 ); subRound3( 54 ); subRound3( 55 );
    subRound3( 56 ); subRound3( 57 ); subRound3( 58 ); subRound3( 59 );
    subRound4( 60 ); subRound4( 61 ); subRound4( 62 ); subRound4( 63 );
    subRound4( 64 ); subRound4( 65 ); subRound4( 66 ); subRound4( 67 );
    subRound4( 68 ); subRound4( 69 ); subRound4( 70 ); subRound4( 71 );
    subRound4( 72 ); subRound4( 73 ); subRound4( 74 ); subRound4( 75 );
    subRound4( 76 ); subRound4( 77 ); subRound4( 78 ); subRound4( 79 );

    /* Step E.  Build message digest */
    shsInfo->digest[ 0 ] += A;
    shsInfo->digest[ 1 ] += B;
    shsInfo->digest[ 2 ] += C;
    shsInfo->digest[ 3 ] += D;
    shsInfo->digest[ 4 ] += E;
    }

#ifdef LITTLE_ENDIAN

/* When run on a little-endian CPU we need to perform byte reversal on an
   array of longwords.  It is possible to make the code endianness-
   independant by fiddling around with data at the byte level, but this
   makes for very slow code, so we rely on the user to sort out endianness
   at compile time */

static void byteReverse( buffer, byteCount )
  LONG *buffer;
  int byteCount;

    {
    LONG value;
    int count;

    byteCount /= sizeof( LONG );
    for( count = 0; count < byteCount; count++ )
	{
	value = ( buffer[ count ] << 16 ) | ( buffer[ count ] >> 16 );
	buffer[ count ] = ( ( value & 0xFF00FF00L ) >> 8 ) | ( ( value & 0x00FF00FFL ) << 8 );
	}
    }
#endif /* LITTLE_ENDIAN */

/* Update SHS for a block of data.  This code assumes that the buffer size
   is a multiple of SHS_BLOCKSIZE bytes long, which makes the code a lot
   more efficient since it does away with the need to handle partial blocks
   between calls to shsUpdate() */

void shsUpdate( shsInfo, buffer, count )
  SHS_INFO *shsInfo;
  BYTE *buffer;
  int count;

    {
    /* Update bitcount */
    if( ( shsInfo->countLo + ( ( LONG ) count << 3 ) ) < shsInfo->countLo )
	shsInfo->countHi++; /* Carry from low to high bitCount */
    shsInfo->countLo += ( ( LONG ) count << 3 );
    shsInfo->countHi += ( ( LONG ) count >> 29 );

    /* Process data in SHS_BLOCKSIZE chunks */
    while( count >= SHS_BLOCKSIZE )
	{
	memcpy( shsInfo->data, buffer, SHS_BLOCKSIZE );
#ifdef LITTLE_ENDIAN
	byteReverse( shsInfo->data, SHS_BLOCKSIZE );
#endif /* LITTLE_ENDIAN */
	shsTransform( shsInfo );
	buffer += SHS_BLOCKSIZE;
	count -= SHS_BLOCKSIZE;
	}

    /* Handle any remaining bytes of data.  This should only happen once
       on the final lot of data */
    memcpy( shsInfo->data, buffer, count );
    }

void shsFinal( shsInfo )
  SHS_INFO *shsInfo;

    {
    int count;
    LONG lowBitcount = shsInfo->countLo, highBitcount = shsInfo->countHi;

    /* Compute number of bytes mod 64 */
    count = ( int ) ( ( shsInfo->countLo >> 3 ) & 0x3F );

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    ( ( BYTE * ) shsInfo->data )[ count++ ] = 0x80;

    /* Pad out to 56 mod 64 */
    if( count > 56 )
	{
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset( ( BYTE * ) &shsInfo->data + count, 0, 64 - count );
#ifdef LITTLE_ENDIAN
	byteReverse( shsInfo->data, SHS_BLOCKSIZE );
#endif /* LITTLE_ENDIAN */
	shsTransform( shsInfo );

	/* Now fill the next block with 56 bytes */
	memset( &shsInfo->data, 0, 56 );
	}
    else
	/* Pad block to 56 bytes */
	memset( ( BYTE * ) &shsInfo->data + count, 0, 56 - count );
#ifdef LITTLE_ENDIAN
    byteReverse( shsInfo->data, SHS_BLOCKSIZE );
#endif /* LITTLE_ENDIAN */

    /* Append length in bits and transform */
    shsInfo->data[ 14 ] = highBitcount;
    shsInfo->data[ 15 ] = lowBitcount;

    shsTransform( shsInfo );
#ifdef LITTLE_ENDIAN
    byteReverse( shsInfo->data, SHS_DIGESTSIZE );
#endif /* LITTLE_ENDIAN */
    }


/* ------------ END OF SHS IMPLEMENTATION ------------ */

/* This can use other hashes, even a homegrown one, if necessary. */

void hash(char *buffer, int buflen, char *result){
        SHS_INFO s;
        int i;
        char *cp;

        shsInit(&s);
        shsUpdate(&s,buffer,buflen);
        shsFinal(&s);

        cp = (char *)s.digest;
	for(i=0;i<20;i++)
		result[i] = cp[i];
}

/* Function prototypes for lfg structure. */

void lfg_create(lfg *, int, int);
void lfg_delete(lfg *);
void lfg_get(lfg*, u4 *, int *);
void lfg_step(lfg *, u4 *, int *);
void lfg_fill(lfg *, u4 *);


typedef struct {
	lfg *a0, *a1, *a2;
        lfg r0,r1,r2;
	int c0,c1,c2,m;
	u4 t0,t1,t2;
} pike;

/* Function prototypes for pike cipher structure. */

void pike_create(pike *);
void pike_delete(pike *);
void pike_encrypt(pike *, u4 *, int );
#define pike_decrypt(p,data,len) pike_encrypt(p,data,len)
void pike_key(pike *, unsigned char *, int );


/* ------------------------------------------------------------------ */
/* Function and method definitions appear here. */
/* ------------------------------------------------------------------ */


#define min(a,b) ((a)>(b)?(b):(a))

/* lagged fibonacci generator methods: */

/* Initialize memory and accept starting parameters. */
void lfg_create(lfg *me, int xlen, int xtap){
        if(me==NULL){
                printf("FATAL ERROR IN LFG_CREATE().\n");
                exit(-1);
        }
        me->len = xlen;
        me->tap = xtap;
        me->reg = (u4 *)malloc(xlen*4);
        me->pos = me->carry = me->curr = 0;
        me->tpos = me->pos+me->tap;
        if(me->tpos>me->len) me->tpos-=xlen;
}

void lfg_delete(lfg *me) {
        free(me->reg);
}

/* Get current value and carry. */
void lfg_get(lfg *me,u4 *xcurr, int *xcarry){
	*xcurr = me->curr;
	*xcarry = me->carry;
	return;
}

/* Fill the register with new data, and reset the position, */
/* current value, and carry to 0. */
void lfg_fill(lfg *me, u4 *data){
	int i;
        for(i=0;i<me->len;i++) me->reg[i] = data[i];
        me->curr = me->pos = me->carry = 0;
        me->tpos = me->pos+me->tap;if(me->tpos>me->len) me->tpos -=me->len;

	return;
}

void lfg_step(lfg *me, u4 *xcurr, int *xcarry){
	u4 t;

/* Calculate next value and determine carry bit. */

	t = min(me->reg[me->pos],me->reg[me->tpos]);
	me->curr = me->reg[me->pos++]+me->reg[me->tpos++];
	if(t>me->curr) me->carry=1;else me->carry=0; /* If we've wrapped around, */
						     /* then carry bit is on. */

/* Update positions. */

	if(me->pos==me->len) me->pos=0;
	if(me->tpos==me->len) me->tpos=0;

/* Send back results. */
	*xcurr=me->curr;
	*xcarry=me->carry;
	return;
}

/* PIKE methods appear here. */

void pike_create(pike *p){
	p->c0=p->c1=p->c2=0;
	p->t0=p->t1=p->t2=0;
	p->m=0;

        p->a0 = &(p->r0);
        p->a1 = &(p->r1);
        p->a2 = &(p->r2);

        if((p->a0==NULL)||(p->a1==NULL)||(p->a2==NULL)){
                printf("Fatal error in pike_create().\n");
                exit(-1);
        }

        lfg_create(p->a0,55,31); /* These look right to me--verify them. */
        lfg_create(p->a1,57,50); /* --John Kelsey, Dec 1994. */
        lfg_create(p->a2,58,39); /* */
}

void pike_delete(pike *p){
        lfg_delete(p->a0);
        lfg_delete(p->a1);
        lfg_delete(p->a2);
}

/* This function (method) takes a pointer to some word-alligned data, and a */
/* number of 32-bit words to encrypt, and encrypts them under the current */
/* cipher state.  The cipher state advances, so that it's possible to encrypt */
/* a buffer of 1000 32-bit words all at one time, or in smaller chunks (say, */
/* 200 32-bit words at a time) with the same results. */

void pike_encrypt(pike *p,u4 *data, int len){
	int i;
	u4 x;

	lfg_get(p->a0,&(p->t0),&(p->c0));
	lfg_get(p->a1,&(p->t1),&(p->c1));
	lfg_get(p->a2,&(p->t2),&(p->c2));

	for(i=0;i<len;i++){

		/* Generate next keystream symbol. */
		p->m = (p->c0&p->c1)|(p->c1&p->c2)|(p->c0&p->c2);
		if(p->c0==p->m) lfg_step(p->a0,&(p->t0),&(p->c0));
		if(p->c1==p->m) lfg_step(p->a1,&(p->t1),&(p->c1));
		if(p->c2==p->m) lfg_step(p->a2,&(p->t2),&(p->c2));
		x = p->t0^p->t1^p->t2;

		/* Encrypt next 32-bit word. */
		data[i]^=x;
	}

	return;
}

/* The key function (method) of the cipher takes a pointer to some bytes of */
/* key, and the key length.  It initializes the cipher internal state to */
/* something that should look random. */
/* */
/* key:  This routine is the part of PIKE that wasn't originally specified */
/*       by Ross Anderson.  Here, I've implemented it using SHA to munge */
/*       up the key material used.  This is almost certainly better than */
/*       any simple key-scheduling scheme that might otherwise be used. */
/*       Note that the key-expansion has to be good for PIKE, because */
/*       most small changes in expanded key result in only small changes */
/*       in keystream. */
/* */

void pike_key(pike *p, unsigned char *keyptr, int keylen){
	u4 xk[170];
	int i,j;
	unsigned char *cp, *cx;

	/* Fill the buffer. */
	cp = (char*)xk;
	for(i=0;i<170*4;i++) cp[i] = keyptr[i % keylen];

	/* Replace the first byte with the key length. */
	cp[0] = keylen;

	/* Use a hash function to munge the buffer hopelessly. */
	/* Hash call must allow for overlap of inputs and outputs. */
	for(i=0;i<170*4;i+=20)
		hash(cp,170*4,cp+i);

	lfg_fill(p->a0, xk);
	lfg_fill(p->a1, xk+55);
	lfg_fill(p->a2, xk+55+57);

	/* Clobber the xk data, so we don't leave it lying around for */
	/* the next application to see. */
	for(i=0;i<170;i++) xk[i]=0;

	return;
}


/* -------------------------------------------------------------------- */
/* Main program appears here. */
/* -------------------------------------------------------------------- */
/* */
/* This can probably serve as a test suite: */
/* */
/* Test 1:  Key with 8-byte sequence (0,0,0,0,0,0,0,0). */
/*          Encrypt buffer of 1000 32-bit 0's.  Record the */
/*          mod 2**32 sum of this buffer, and the XOR of it. */
/* */
/* Test 2:  Key with 4-byte sequence (1,2,3,4). */
/*          Encrypt buffer of 1000 32-bit 0's.  Record the */
/*          mod 2**32 sum and XOR of this buffer. */
/* */
/* Test 3:  Key with 3-byte sequence (0,0,0) to demonstrate that */
/*          keys differing only in length will expand differently. */
/* */
void main(void) {
	pike p;
	u4 test_buff[1000],s1,x1,s2,x2,s3,x3;
	u4 t;
	int i,flag,count,j;
	char k1[]={0,0,0,0,0,0,0,0}, k2[]={1,2,3,4},k3[]={0,0,0};

/*-------------------------------------------------------------------------
			 GENERATE TEST VECTORS
-------------------------------------------------------------------------*/
	/* Test 1: k= {0,0,0,0,0,0,0,0} */
	/* Key cipher for first test. */
          pike_create(&p);
          pike_key(&p,k1,8);

	/* Clear buffer for first test. */
        for(i=0;i<1000;i++)test_buff[i] = 0;

	/* Fill buffer. */
        pike_encrypt(&p,test_buff,1000);

	/* Find XOR and SUM: */
        s1=x1=0;
	for(i=0;i<1000;i++){
		s1+=test_buff[i];
		x1^=test_buff[i];
	}
	printf("8-byte all zero key generates: XOR = %08lx, SUM = %08lx\n",
                x1,s1);

/*--------------------------------------------------------------------------
				ENC/DEC TEST
--------------------------------------------------------------------------*/

	/* Verify that decrypt() reverses encrypt(), even when called */
	/* in different increments. */

        pike_key(&p,k3,3);
        for(i=0;i<1000;i++) test_buff[i]=0;
        pike_encrypt(&p,test_buff,1000);
        pike_key(&p,k3,3);
        t = 0;
        for(i=0;i<1000;i++) t = t ^ test_buff[i];
        printf("XOR is %08lx.\n",t);
        pike_decrypt(&p,test_buff,1);
        pike_decrypt(&p,test_buff+1,999);
        pike_delete(&p);

        flag =1;
        for(i=0;i<1000;i++) if(test_buff[i]!=0)flag =0;
        if(flag) printf("Passed enc/dec test.\n");
        else printf("Failed enc/dec test.\n");

}


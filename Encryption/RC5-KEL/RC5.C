From uucp Mon Mar 20 06:14 CST 1995
Received: from Mailbox by chinet.chinet.com; Mon, 20 Mar 95 06:14 CST
Received: by mailbox.mcs.com (/\==/\ Smail3.1.28.1 #28.5)
	id <m0rqfNt-000jopC@mailbox.mcs.com>; Mon, 20 Mar 95 05:12 CST
Received: by mercury.mcs.com (/\==/\ Smail3.1.28.1 #28.5)
	id <m0rqfNs-000Bk6C@mercury.mcs.com>; Mon, 20 Mar 95 05:12 CST
Received: from delphi.com by delphi.com (PMDF V4.3-9 #7804)
 id <01HOCKHZ8AXW8Y8JIE@delphi.com>; Mon, 20 Mar 1995 06:12:25 -0500 (EST)
Date: Mon, 20 Mar 1995 06:12:25 -0500 (EST)
From: JMKELSEY@delphi.com
Subject: RC5 implementation
To: schneier@chinet.com
Message-id: <01HOCKHZ8AXY8Y8JIE@delphi.com>
X-VMS-To: INTERNET"schneier@chinet.com"
MIME-version: 1.0
Content-Length: 6341
Content-Type: TEXT/PLAIN; CHARSET=US-ASCII
Content-transfer-encoding: 7BIT
Status: O

#include <stdio.h>
/* --------------------------------------------------------------------
** RC5 -- a block cipher designed by Ron Rivest.
** Implementation by John Kelsey, jmkelsey@delphi.com, March 1995.
** This implementation is in the public domain, but RC5 may be patented.
** Check with Rivest or RSA Data Security for details.
**
** This program implements RC5-32/r/b for user-specified r and b.
** (r = number of rounds, b = number of bytes in key)
-------------------------------------------------------------------- */
typedef unsigned char u1;
typedef unsigned long u4;

/* An RC5 context needs to know how many rounds it has, and its subkeys. */
typedef struct {
        u4 *xk;
        int nr;
} rc5_ctx;

/* Where possible, these should be replaced with actual rotate instructions.
   For Turbo C++, this is done with _lrotl and _lrotr. */

#define ROTL32(X,C) (((X)<<(C))|((X)>>(32-(C))))
#define ROTR32(X,C) (((X)>>(C))|((X)<<(32-(C))))

/* Function prototypes for dealing with RC5 basic operations. */
void rc5_init(rc5_ctx *, int);
void rc5_destroy(rc5_ctx *);
void rc5_key(rc5_ctx *, u1 *, int);
void rc5_encrypt(rc5_ctx *, u4 *, int);
void rc5_decrypt(rc5_ctx *, u4 *, int);


/* Function implementations for RC5. */

/* Scrub out all sensitive values. */
void rc5_destroy(rc5_ctx *c){
        int i;
	for(i=0;i<(c->nr)*2+2;i++) c->xk[i]=0;
	free(c->xk);
}

/* Allocate memory for rc5 context's xk and such. */
void rc5_init(rc5_ctx *c, int rounds){
	c->nr = rounds;
	c->xk = (u4 *) malloc(4*(rounds*2+2));
}

/*
**      rc5_encrypt(context,data_ptr,count_of_blocks_to_encrypt)
**      This function encrypts several blocks with RC5 in ECB mode.
**      *Which* version of RC5 (ie, how many rounds and how much key)
**      is set up in rc5_key() for this context.  Padding out short
**      blocks is the user's responsibility--this function is only
**      interested in how many 64-bit blocks you have.
**
**      RC5's round structure is very simple and should compile down to
**      something very efficient on 32-bit architectures.  On 16-bit
**      architectures like the 8086, RC5 (actually, RC5-32) may not be
**      quite so fast.
*/
void rc5_encrypt(rc5_ctx *c, u4 *data, int blocks){
        u4 *d,*sk;
        int h,i,rc;

	d = data;
        sk = (c->xk)+2;
        for(h=0;h<blocks;h++){
                d[0] += c->xk[0];
                d[1] += c->xk[1];
                for(i=0;i<c->nr*2;i+=2){
                        d[0] ^= d[1];
                        rc = d[1] & 31;
                        d[0] = ROTL32(d[0],rc);
                        d[0] += sk[i];
			d[1] ^= d[0];
                        rc = d[0] & 31;
                        d[1] = ROTL32(d[1],rc);
                        d[1] += sk[i+1];
/*printf("Round %03d : %08lx %08lx  sk= %08lx %08lx\n",i/2,
                                d[0],d[1],sk[i],sk[i+1]);*/
                }
		d+=2;
        }
}

/*
**      rc5_decrypt(context,data_ptr,count_of_blocks_to_decrypt)
**      This function decrypts a bunch of blocks with RC5 in ECB mode.
**      Padding short blocks is the user's responsibility.
*/
void rc5_decrypt(rc5_ctx *c, u4 *data, int blocks){
	u4 *d,*sk;
        int h,i,rc;

	d = data;
        sk = (c->xk)+2;
	for(h=0;h<blocks;h++){
                for(i=c->nr*2-2;i>=0;i-=2){
/*printf("Round %03d: %08lx %08lx  sk: %08lx %08lx\n",
        i/2,d[0],d[1],sk[i],sk[i+1]); */
                        d[1] -= sk[i+1];
                        rc = d[0] & 31;
                        d[1] = ROTR32(d[1],rc);
                        d[1] ^= d[0];

                        d[0] -= sk[i];
                        rc = d[1] & 31;
                        d[0] = ROTR32(d[0],rc);
			d[0] ^= d[1];
                }
                d[0] -= c->xk[0];
                d[1] -= c->xk[1];
        d+=2;
	}
}

/*
**      rc5_key(context,key_pointer,key_len,rounds)
**      This implements the RC5 key scheduling algorithm for the
**      specified key length and number of rounds.  The key schedule
**      is fairly complex in C code, but conceptually, it boils down
**      to this:
**
**      1.  Pad the key out to the next 32-bit word.
**      2.  Initialize the expanded key array to a predefined
**          pseudorandom value.
**      3.  Initialize two chaining values, A and B, to 0.
**      4.  Make several passes through the expanded and padded key
**          arrays, adding A and B to the next expanded key entry and then
**          rotating it left 3 bits, and setting A to that entry, and
**          then adding A and B to next padded key entry, and rotating
**          it by (A + B) mod 32 bits, and setting B to that result.
**
*/
void rc5_key(rc5_ctx *c, u1 *key, int keylen){
	u4 *pk,A,B; /* padded key */
	int xk_len, pk_len, i, num_steps,rc;
	u1 *cp;

	xk_len = c->nr*2 + 2;
	pk_len = keylen/4;
	if((keylen%4)!=0) pk_len += 1;

	pk = (u4 *) malloc(pk_len * 4);
	if(pk==NULL) {
		printf("An error occurred!\n");
		exit(-1);
	}

	/* Initialize pk -- this should work on Intel machines, anyway.... */
	for(i=0;i<pk_len;i++) pk[i]=0;
	cp = (u1 *)pk;
	for(i=0;i<keylen;i++) cp[i]=key[i];

	/* Initialize xk. */
	c->xk[0] = 0xb7e15163; /* P32 */
	for(i=1;i<xk_len;i++) c->xk[i] = c->xk[i-1] + 0x9e3779b9; /* Q32 */

	/* TESTING */
	A = B = 0;
	for(i=0;i<xk_len;i++) {
		A = A + c->xk[i];
		B = B ^ c->xk[i];
	}

	/* Expand key into xk. */
	if(pk_len>xk_len) num_steps = 3*pk_len;else num_steps = 3*xk_len;

	A = B = 0;
	for(i=0;i<num_steps;i++){
		A = c->xk[i%xk_len] = ROTL32(c->xk[i%xk_len] + A + B,3);
		rc = (A+B) & 31;
		B = pk[i%pk_len] = ROTL32(pk[i%pk_len] + A + B,rc);

	}

	/* Clobber sensitive data before deallocating memory. */
	for(i=0;i<pk_len;i++) pk[i] =0;

	free(pk);
}

void main(void){
	rc5_ctx c;
	u4 data[8];
	char key[] = "ABCDE";
	int i;

	printf("-------------------------------------------------\n");

        for(i=0;i<8;i++) data[i] = i;
	rc5_init(&c,10); /* 10 rounds */
	rc5_key(&c,key,5);

        rc5_encrypt(&c,data,4);
        printf("Encryptions:\n");
        for(i=0;i<8;i+=2) printf("Block %01d = %08lx %08lx\n",
                                 i/2,data[i],data[i+1]);
        rc5_decrypt(&c,data,2);
	rc5_decrypt(&c,data+4,2);
        printf("Decryptions:\n");
        for(i=0;i<8;i+=2) printf("Block %01d = %08lx %08lx\n",
                                 i/2,data[i],data[i+1]);

}


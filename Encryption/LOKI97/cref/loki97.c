/*
 * Implements the LOKI97 block cipher.<p>
 *
 * LOKI97 is a 128-bit symmetric block cipher with a 256-bit key schedule,
 * which may be initialised from 128, 192, or 256-bit keys. It uses 16 rounds
 * of data computation using a balanced feistel network with a complex
 * function f which incorporates two S-P layers. The 256-bit key schedule
 * uses 33 rounds of an unbalanced feistel network using the same complex
 * function f to generate the subkeys.<p>
 *
 * LOKI97 was written by Lawrie Brown (ADFA), Josef Pieprzyk, and Jennifer
 * Seberry (UOW) in 1997.<p>
 *
 * <b>Copyright</b> &copy; 1998 by <a href="mailto:Lawrie.Brown@adfa.oz.au">
 * Lawrie Brown</a> & ITRACE (UNSW)
 *
 * <br>All rights reserved.<p>
 *
 * Author:  Lawrie Brown
 *
 * code derived from LOKI97 java implementation by Lawrie Brown & Raif Naffah
 */

/* include standard AES C header file */
#include "loki97.h"

/* Global defines and variables */

#define NAME	"LOKI97"
#define DEBUG	0

/*
 * Debug diagnostics. Valid values of symbolic constant DEBUG: <p>
 *
 * Values are:<dl compact>
 * <dt> 1 <dd> engine calls,
 * <dt> 2 <dd> enc/dec round values,
 * <dt> 3 <dd> subkeys,
 * <dt> 4 <dd> func f calls,
 * <dt> 5 <dd> func f internals,
 * <dt> 6 <dd> static init. </dl>
 */
#define debuglevel DEBUG 


/*  LOKI97 algorithm specific constants and tables */
/* ........................................................................... */

/* Generator polynomial for S-box S1, in GF(2<sup>13</sup>). */
#define S1_GEN 0x2911

/* Size of S-box S1, for 13-bit inputs. */
#define S1_SIZE 0x2000

/* Table of pre-computed S-box S1 values. */
static BYTE S1[S1_SIZE];

/* Generator polynomial for S-box S2, in GF(2<sup>11</sup>). */
#define S2_GEN 0xAA7

/* Size of S-box S2, for 11-bit inputs. */
#define S2_SIZE 0x800

/* Table of pre-computed S-box S2 values. */
static BYTE S2[S2_SIZE];

/* Constant value for Delta which is used in the key schedule */
static ULONG64 DELTA = {0x9E3779B9L, 0x7F4A7C15L};

/*
 * Table specifying the pre-computed permutation P.
 * nb. precompute permutations for lowest 8 bits only,
 *     value of P is a 64-bit wide (long) mask of the permuted input value.
 */
static ULONG64 P[0x100];

/* Flag specifying whether once-off init of S1, S2 and P has been done */
static int init_done = FALSE;

/* prototypes for local utility functions */
static int enECB(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer);
static int enCBC(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer);
static int enCFB1(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer);
static int deECB(cipherInstance *cipher, keyInstance *key, BYTE *input,
		int inputLen, BYTE *outBuffer);
static int deCBC(cipherInstance *cipher, keyInstance *key, BYTE *input,
		int inputLen, BYTE *outBuffer);
static int deCFB1(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer);
static ULONG64 f (ULONG64 A, ULONG64 B) ;
static ULONG64 add64(ULONG64 a, ULONG64 b) ;
static ULONG64 sub64(ULONG64 a, ULONG64 b) ;
static int exp3 (int b, int g, int n) ;
static int mult (int a, int b, int g, int n) ;
static ULONG64 byteToULONG64(BYTE *inp) ;
static BYTE *ULONG64ToBYTE(BYTE *buf, ULONG64 I) ;
static BYTE *charToBYTE(BYTE *buf, char *hex, int len) ;
static ULONG64 charToULONG64(char *hex) ;
static int fromHex (char ch) ;
static int puthex(BYTE *out, int len, FILE *f);


/*  Initialise cipher, precompute S-boxes and permutation table */
/* ......................................................................... */

int cipherInit(cipherInstance *cipher, BYTE mode, char *IV)
{
    int S1_MASK = S1_SIZE - 1;	/*  mask to select S1 input bits */
    int S2_MASK = S2_SIZE - 1;	/*  mask to select S2 input bits */

    int i, j, k;		/*  index into S-box, P bit , out bit */
    int b;			/*  S-box fn input */
    long pval;			/*  perm P mask for given input value */
    BYTE *input;		/*  pointer into byte array for IV */

    if (debuglevel) fprintf(stderr,"%s: cipherInit(mode=%d, IV=%s)\n", NAME, mode, IV);

    if (!init_done) {

        /*  precompute S-box tables for S1 and S2 */
        if (debuglevel > 5) fprintf(stderr,"%s: Static init of S1, S2 & P \n", NAME);
        for (i = 0; i < S1_SIZE; i++) { /*  for all S1 inputs */
            b = i ^ S1_MASK; /*  compute input value */
            S1[i] = exp3(b, S1_GEN, S1_SIZE); /*  compute fn value */
            if (debuglevel > 5) fprintf(stderr,"%s: S1[%04X] = %02X\n", NAME, i, S1[i]);
        }
        for (i = 0; i < S2_SIZE; i++) { /*  for all S2 inputs */
            b = i ^ S2_MASK; /*  compute input value */
            S2[i] = exp3(b, S2_GEN, S2_SIZE); /*  compute fn value */
            if (debuglevel > 5) fprintf(stderr,"%s: S2[%04X] = %02X\n", NAME, i, S2[i]);
        }
    
        /*  initialising expanded permutation P table (for lowest BYTE only) */
        /*    Permutation P maps input bits [63..0] to outputs bits: */
        /*    [56, 48, 40, 32, 24, 16,  8, 0, */
        /*     57, 49, 41, 33, 25, 17,  9, 1, */
        /*     58, 50, 42, 34, 26, 18, 10, 2, */
        /*     59, 51, 43, 35, 27, 19, 11, 3, */
        /*     60, 52, 44, 36, 28, 20, 12, 4, */
        /*     61, 53, 45, 37, 29, 21, 13, 5, */
        /*     62, 54, 46, 38, 30, 22, 14, 6, */
        /*     63, 55, 47, 39, 31, 23, 15, 7]  <- this row only used in table */
        /*   since it is so regular, we can construct it on the fly */
        for (i = 0; i < 0x100; i++) { /*  loop over all 8-bit inputs */
            /*  for each input bit permute to specified output position */
            pval = 0L;
            for (j = 0, k = 7; j < 4; j++, k += 8)	/* do right half of P */
                pval |= (long)((i >> j) & 0x1) << k;
            P[i].r = pval;
            pval = 0L;
            for (j = 4, k = 7; j < 8; j++, k += 8)	/* do left half of P */
                pval |= (long)((i >> j) & 0x1) << k;
            P[i].l = pval;
            if (debuglevel > 5) fprintf(stderr,"%s: P[%02X] = %08X%08X\n", NAME, i, P[i].l, P[i].r);
        }

	/* and remember that init has been done */
	init_done = TRUE;
    }

    /* now fill out cipherInstance structure */
    cipher->mode = mode;				/* copy mode over */
    if (IV != NULL) {					/* IV specified */
	charToBYTE(cipher->IV,IV,sizeof(cipher->IV));	/* convert IV */
        /*  pack IV into IVL and IVR */
	input = cipher->IV;
        cipher->IVL = byteToULONG64(input); input += 8;
        cipher->IVR = byteToULONG64(input); input += 8;
    } else {						/* no IV, so set to 0 */
	memset(cipher->IV,0,sizeof(cipher->IV));
	cipher->IVL.l = cipher->IVL.r = cipher->IVR.l = cipher->IVR.r = 0L;
    }
    cipher->blockSize = BLOCK_SIZE*8;			/* BLOCK_SIZE in bits */

    /* decide correct return value */
    if ((mode == MODE_ECB)||(mode == MODE_CBC)||(mode == MODE_CFB1))
        return TRUE;
    else
        return BAD_CIPHER_MODE;

}


/*
 * Returns residue of base b to power 3 mod g in GF(2^n).
 *
 * @param b  Base of exponentiation, the exponent being always 3.
 * @param g  Irreducible polynomial generating Galois Field (GF(2^n)).
 * @param n  Size of the galois field.
 * @return (b ** 3) mod g.
 */
static int exp3 (int b, int g, int n) {
    int r = b;            /*  r = b */
    if (b == 0)
        return 0;
    b = mult(r, b, g, n); /*  r = b ** 2 */
    r = mult(r, b, g, n); /*  r = b ** 3 */
    return r;
}

/*
 * Returns the product of two binary numbers a and b, using the
 * generator g as the modulus: p = (a * b) mod g. g Generates a
 * suitable Galois Field in GF(2^n).
 *
 * @param a  First multiplicand.
 * @param b  Second multiplicand.
 * @param g  Irreducible polynomial generating Galois Field.
 * @param n  Size of the galois field.
 * @return (a * b) mod g.
 */
static int mult (int a, int b, int g, int n) {
    int p = 0;
    while (b != 0) {
        if ((b & 0x01) != 0)
            p ^= a;
        a <<= 1;
        if (a >= n)
            a ^= g;
        b >>= 1;
    }
    return p;
}


/*  Basic NIST API methods for LOKI97 */
/* ......................................................................... */

/* Expand a user-supplied key material into a LOKI97 session key.  */
int makeKey(keyInstance *key, BYTE direction, int keyLen, char *keyMaterial)
{
    ULONG64 k4, k3, k2, k1;		/*  key schedule 128-bit entities */
    ULONG64 deltan = DELTA;		/*  multiples of delta */
    ULONG64 t1, t2;			/*  temps used for doing 64-bit adds */
    ULONG64 f_out;			/*  fn f output value for debug */
    int i = 0;				/*  index into key input */

    /*  do some basic sanity checks on the keyMaterial */
    if ((key == NULL) || (keyMaterial == NULL)) return BAD_KEY_INSTANCE;
    if (!(direction == DIR_ENCRYPT || direction == DIR_DECRYPT))
        return BAD_KEY_DIR;
    if (!(keyLen == 128 || keyLen == 192 || keyLen == 256))
        return BAD_KEY_MAT;

    /* fill out the keyInstance structure with input params */
    key->direction = direction;
    key->keyLen = keyLen;
    strncpy(key->keyMaterial, keyMaterial, MAX_KEY_SIZE);

    /*  convert ascii hex text into into 64-bit entities: k4, k3, k2, k1 */
    k4 = charToULONG64(keyMaterial); keyMaterial += 16;
    k3 = charToULONG64(keyMaterial); keyMaterial += 16;
    if (keyLen == 128) {   /*  128-bit key - call fn f twice to gen 256 bits */
        k2 = f(k3, k4);
        k1 = f(k4, k3);
    } else {                /*  192 or 256-bit key - pack k2 from key data */
        k2 = charToULONG64(keyMaterial); keyMaterial += 16;
        if (keyLen == 192) /*  192-bit key - call fn f once to gen 256 bits */
            k1 = f(k4, k3);
        else {              /*  256-bit key - pack k1 from key data */
            k1 = charToULONG64(keyMaterial); keyMaterial += 16;
        }
    }

    if (debuglevel) fprintf(stderr,"%s: makeKey(%08X%08X%08X%08X%08X%08X%08X%08X,%s)\n", NAME, k4.l, k4.r, k3.l, k3.r, k2.l, k2.r, k1.l, k1.r, direction?"Dec":"Enc");

    /*  iterate over all LOKI97 rounds to generate the required subkeys */
    for (i = 0; i < NUM_SUBKEYS; i++) {
	t1 = add64(k1,k3);		/* compute f(k1+k3+n.delta,k2) */
	t2 = add64(t1,deltan);
        f_out = f(t2, k2);
        key->SK[i].l = k4.l ^ f_out.l;	/*  compute next subkey using fn f */
        key->SK[i].r = k4.r ^ f_out.r;
        k4 = k3;			/*  exchange the other words around */
        k3 = k2;
        k2 = k1;
        k1 = key->SK[i];
        deltan = add64(deltan,DELTA);	/*  next multiple of delta */
        if (debuglevel > 2) fprintf(stderr,"%s: SK[%02d]=%08X%08X\t", NAME, i, key->SK[i].l, key->SK[i].r);
        if (debuglevel > 2) fprintf(stderr,"f=%08X%08X,\tdeltan=%08X%08X\n", f_out.l, f_out.r, deltan.l, deltan.r);
    }

    return TRUE;
}


/* ....................................................................... */
/*
 * blockEncrypt(cipher,key,input,inputLen,outBuffer) -
 *     encrypt blocks of plaintext from input to outBuffer using cipher & key.
 */
int blockEncrypt(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer)
{
    /*  do some basic sanity checks on params */
    if (!init_done) return BAD_CIPHER_STATE;
    if (cipher == NULL) return BAD_CIPHER_STATE;
    if (key == NULL) return BAD_KEY_INSTANCE;
    if (key->direction != DIR_ENCRYPT) return BAD_KEY_DIR;

    /* now call appropriate mode encrypt routine */
    if (cipher->mode == MODE_ECB)
	return enECB(cipher, key, input, inputLen, outBuffer);
    else if (cipher->mode == MODE_CBC)
	return enCBC(cipher, key, input, inputLen, outBuffer);
    else if (cipher->mode == MODE_CFB1)
	return enCFB1(cipher, key, input, inputLen, outBuffer);
    else
        return BAD_CIPHER_MODE;
}


/*
 * encrypt blocks in ECB mode
 */
static int enECB(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer)
{
    int i,j,k;			/* assorted loop counters */
    int blocks = inputLen / (BLOCK_SIZE*8);	/* compute # input blocks */
    ULONG64 L, R;		/* left and right data blocks */
    ULONG64 nR, f_out;

    /*  do some basic sanity checks on params */
    if (inputLen % (BLOCK_SIZE*8) != 0) return BAD_CIPHER_INPUT;

    /* now loop over all blocks of input */
    for (j = 0; j < blocks; j++) {

        /*  pack input block into L and R */
        L = byteToULONG64(input); input += 8;
        R = byteToULONG64(input); input += 8;

        if (debuglevel) fprintf(stderr,"%s: enECB(%08X%08X%08X%08X) ", NAME, L.l, L.r, R.l, R.r);
        if (debuglevel > 1) fprintf(stderr,"\n");

        /*  compute all rounds for this 1 block */
        k = 0;
        for (i = 0; i < ROUNDS; i++) {
            nR = add64(R, key->SK[k++]);		/* nR = R+SK(k) */
            f_out = f(nR, key->SK[k++]);		/* f = f(nR,SK(k+1)) */
            nR = add64(nR, key->SK[k++]);		/* nR = nR+SK(k+2) */
            R.l = L.l ^ f_out.l; R.r = L.r ^ f_out.r;	/* R = L XOR f */
            L = nR;					/* L = nR */
            if (debuglevel > 1) fprintf(stderr," L[%02d]=%08X%08X; R[%02d]=%08X%08X; f(SK(%02d))=%08X%08X\n", i+1, L.l, L.r, i+1, R.l, R.r, k-2, f_out.l, f_out.r);
        }

        if (debuglevel > 0) fprintf(stderr,"= %08X%08X%08X%08X\n", R.l, R.r, L.l, L.r);

        /*  unpack resulting L & R into output - undoing last swap */
	ULONG64ToBYTE(outBuffer, R); outBuffer += 8;
	ULONG64ToBYTE(outBuffer, L); outBuffer += 8;
    }
    return TRUE;
}


/*
 * encrypt blocks in CBC mode
 */
static int enCBC(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer)
{
    int i,j,k;			/* assorted loop counters */
    int blocks = inputLen / (BLOCK_SIZE*8);	/* compute # input blocks */
    ULONG64 L, R;		/* left and right data blocks */
    ULONG64 nR, f_out;

    /*  do some basic sanity checks on params */
    if (inputLen % (BLOCK_SIZE*8) != 0) return BAD_CIPHER_INPUT;

    /* now loop over all blocks of input */
    for (j = 0; j < blocks; j++) {

        /*  pack input block into L and R */
        L = byteToULONG64(input); input += 8;
        R = byteToULONG64(input); input += 8;

        /* XOR with IV value */
	L.l ^= cipher->IVL.l; L.r ^= cipher->IVL.r;
	R.l ^= cipher->IVR.l; R.r ^= cipher->IVR.r;

        if (debuglevel) fprintf(stderr,"%s: enCBC(%08X%08X%08X%08X) ", NAME, L.l, L.r, R.l, R.r);
        if (debuglevel > 1) fprintf(stderr,"\n");

        /*  compute all rounds for this 1 block */
        k = 0;
        for (i = 0; i < ROUNDS; i++) {
            nR = add64(R, key->SK[k++]);		/* nR = R+SK(k) */
            f_out = f(nR, key->SK[k++]);		/* f = f(nR,SK(k+1)) */
            nR = add64(nR, key->SK[k++]);		/* nR = nR+SK(k+2) */
            R.l = L.l ^ f_out.l; R.r = L.r ^ f_out.r;	/* R = L XOR f */
            L = nR;					/* L = nR */
            if (debuglevel > 1) fprintf(stderr," L[%02d]=%08X%08X; R[%02d]=%08X%08X; f(SK(%02d))=%08X%08X\n", i+1, L.l, L.r, i+1, R.l, R.r, k-2, f_out.l, f_out.r);
        }

        /* save new IV value (nb. undo last swap, as per output transform */
	cipher->IVL = R; cipher->IVR = L;

        if (debuglevel > 0) fprintf(stderr,"= %08X%08X%08X%08X\n", R.l, R.r, L.l, L.r);

        /*  unpack resulting L & R into output - undoing last swap */
	ULONG64ToBYTE(outBuffer, R); outBuffer += 8;
	ULONG64ToBYTE(outBuffer, L); outBuffer += 8;
    }
    return TRUE;
}


/*
 * encrypt blocks in CFB1 mode
 */
static int enCFB1(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer)
{
    int i,j,k;			/* assorted loop counters */
    int b;			/* bit number being processed in byte */
    BYTE msgbit, keybit;	/* current message and stream key bits */
    ULONG64 L, R;		/* left and right data blocks */
    ULONG64 nR, f_out;

    /* get CFB1 input buffer from IV */
    L = cipher->IVL; R = cipher->IVR;

    /* get ready to process first byte */
    b = 7;			/* start with top bit in byte */
    *outBuffer = 0;		/* and zero byte in outBuffer */

    /* now loop over all bits of input */
    for (j = 0; j < inputLen; j++) {
        msgbit = (*input >> b) & 01;			/* get next msg bit */

        if (debuglevel) fprintf(stderr,"%s: enCFB1(%01X,%08X%08X%08X%08X) ", NAME, msgbit, L.l, L.r, R.l, R.r);
        if (debuglevel > 1) fprintf(stderr,"\n");

        /*  compute all rounds to encrypt current CFB1 buffer */
        k = 0;
        for (i = 0; i < ROUNDS; i++) {
            nR = add64(R, key->SK[k++]);		/* nR = R+SK(k) */
            f_out = f(nR, key->SK[k++]);		/* f = f(nR,SK(k+1)) */
            nR = add64(nR, key->SK[k++]);		/* nR = nR+SK(k+2) */
            R.l = L.l ^ f_out.l; R.r = L.r ^ f_out.r;	/* R = L XOR f */
            L = nR;					/* L = nR */
            if (debuglevel > 1) fprintf(stderr," L[%02d]=%08X%08X; R[%02d]=%08X%08X; f(SK(%02d))=%08X%08X\n", i+1, L.l, L.r, i+1, R.l, R.r, k-2, f_out.l, f_out.r);
        }
	/* undo last swap */
	L = R; R = nR;

	/* now process msgbit by getting stream key bit, XOR in and or to out */
	keybit = L.l >> 31;
	msgbit ^= keybit;
	*outBuffer |= (msgbit << b);

        if (debuglevel > 0) fprintf(stderr,"= %01X,%08X%08X%08X%08X\n", msgbit, L.l, L.r, R.l, R.r);

	/* and update the CFB1 shift register (input buffer L,R) */
	L.l = (L.l << 1) | (L.r >> 31); L.r = (L.r << 1) | (R.l >> 31);
	R.l = (R.l << 1) | (R.r >> 31); R.r = (R.r << 1) | msgbit;

	/* and update bit position counter */
	b--;
	/* and move to next input/output byte if necessary */
	if (b<0) { b = 7; input++; outBuffer++; *outBuffer = 0; }
    }

    /* save new IV value */
    cipher->IVL = L; cipher->IVR = R;
    return TRUE;
}



/* ....................................................................... */
/*
 * blockDecrypt(cipher,key,input,inputLen,outBuffer) -
 *     decrypt blocks of plaintext from input to outBuffer using cipher & key.
 */
int blockDecrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
		int inputLen, BYTE *outBuffer)
{
    /*  do some basic sanity checks on params */
    if (!init_done) return BAD_CIPHER_STATE;
    if (cipher == NULL) return BAD_CIPHER_STATE;
    if (key == NULL) return BAD_KEY_INSTANCE;
    if (key->direction != DIR_DECRYPT) return BAD_KEY_DIR;

    /* now call appropriate mode decrypt routine */
    if (cipher->mode == MODE_ECB)
	return deECB(cipher, key, input, inputLen, outBuffer);
    else if (cipher->mode == MODE_CBC)
	return deCBC(cipher, key, input, inputLen, outBuffer);
    else if (cipher->mode == MODE_CFB1)
	return deCFB1(cipher, key, input, inputLen, outBuffer);
    else
        return BAD_CIPHER_MODE;
}


/*
 * decrypt blocks in ECB mode
 */
static int deECB(cipherInstance *cipher, keyInstance *key, BYTE *input,
		int inputLen, BYTE *outBuffer)
{
    int i,j,k;			/* assorted loop counters */
    int blocks = inputLen / (BLOCK_SIZE*8);	/* compute # input blocks */
    ULONG64 L, R;		/* left and right data blocks */
    ULONG64 nR, f_out;

    /*  do some basic sanity checks on params */
    if (inputLen % (BLOCK_SIZE*8) != 0) return BAD_CIPHER_INPUT;

    /* now loop over all blocks of input */
    for (j = 0; j < blocks; j++) {

        /*  pack input block into L and R */
        L = byteToULONG64(input); input += 8;
        R = byteToULONG64(input); input += 8;

        if (debuglevel) fprintf(stderr,"%s: deECB(%08X%08X%08X%08X) ", NAME, L.l, L.r, R.l, R.r);
        if (debuglevel > 1) fprintf(stderr,"\n");

        /*  compute all rounds for this 1 block */
        k = NUM_SUBKEYS - 1;
        for (i = 0; i < ROUNDS; i++) {
            nR = sub64(R, key->SK[k--]);		/* nR = R+SK(k) */
            f_out = f(nR, key->SK[k--]);		/* f = f(nR,SK(k+1)) */
            nR = sub64(nR, key->SK[k--]);		/* nR = nR+SK(k+2) */
            R.l = L.l ^ f_out.l; R.r = L.r ^ f_out.r;	/* R = L XOR f */
            L = nR;					/* L = nR */
            if (debuglevel > 1) fprintf(stderr," L[%02d]=%08X%08X; R[%02d]=%08X%08X; f(SK(%02d))=%08X%08X\n", i+1, L.l, L.r, i+1, R.l, R.r, k+2, f_out.l, f_out.r);
        }

        if (debuglevel > 0) fprintf(stderr,"= %08X%08X%08X%08X\n", R.l, R.r, L.l, L.r);

        /*  unpack resulting L & R into output - undoing last swap */
	ULONG64ToBYTE(outBuffer, R); outBuffer += 8;
	ULONG64ToBYTE(outBuffer, L); outBuffer += 8;
    }
    return TRUE;
}
 

/*
 * Dncrypt blocks in CBC mode
 */
static int deCBC(cipherInstance *cipher, keyInstance *key, BYTE *input,
		int inputLen, BYTE *outBuffer)
{
    int i,j,k;			/* assorted loop counters */
    int blocks = inputLen / (BLOCK_SIZE*8);	/* compute # input blocks */
    ULONG64 L, R;		/* left and right data blocks */
    ULONG64 newIVL, newIVR;	/* next IV L & R halves */
    ULONG64 nR, f_out;

    /*  do some basic sanity checks on params */
    if (inputLen % (BLOCK_SIZE*8) != 0) return BAD_CIPHER_INPUT;

    /* now loop over all blocks of input */
    for (j = 0; j < blocks; j++) {

        /*  pack input block into L and R */
        L = byteToULONG64(input); input += 8;
        R = byteToULONG64(input); input += 8;

        /* save new IV value */
	newIVL = L; newIVR = R;

        if (debuglevel) fprintf(stderr,"%s: deCBC(%08X%08X%08X%08X) ", NAME, L.l, L.r, R.l, R.r);
        if (debuglevel > 1) fprintf(stderr,"\n");

        /*  compute all rounds for this 1 block */
        k = NUM_SUBKEYS - 1;
        for (i = 0; i < ROUNDS; i++) {
            nR = sub64(R, key->SK[k--]);		/* nR = R+SK(k) */
            f_out = f(nR, key->SK[k--]);		/* f = f(nR,SK(k+1)) */
            nR = sub64(nR, key->SK[k--]);		/* nR = nR+SK(k+2) */
            R.l = L.l ^ f_out.l; R.r = L.r ^ f_out.r;	/* R = L XOR f */
            L = nR;					/* L = nR */
            if (debuglevel > 1) fprintf(stderr," L[%02d]=%08X%08X; R[%02d]=%08X%08X; f(SK(%02d))=%08X%08X\n", i+1, L.l, L.r, i+1, R.l, R.r, k+2, f_out.l, f_out.r);
        }

        /* XOR with IV value (undoing last swap) */
	R.l ^= cipher->IVL.l; R.r ^= cipher->IVL.r;
	L.l ^= cipher->IVR.l; L.r ^= cipher->IVR.r;

        /* save IV value */
	cipher->IVL = newIVL; cipher->IVR = newIVR;

        if (debuglevel > 0) fprintf(stderr,"= %08X%08X%08X%08X\n", R.l, R.r, L.l, L.r);

        /*  unpack resulting L & R into output - undoing last swap */
	ULONG64ToBYTE(outBuffer, R); outBuffer += 8;
	ULONG64ToBYTE(outBuffer, L); outBuffer += 8;
    }
    return TRUE;
}


/*
 * decrypt blocks in CFB1 mode
 */
static int deCFB1(cipherInstance *cipher, keyInstance *key, BYTE *input, 
		int inputLen, BYTE *outBuffer)
{
    int i,j,k;			/* assorted loop counters */
    int b;			/* bit number being processed in byte */
    BYTE msgbit, prev, keybit;	/* current & prev message and stream key bits */
    ULONG64 L, R;		/* left and right data blocks */
    ULONG64 nR, f_out;

    /* get CFB1 input buffer from IV */
    L = cipher->IVL; R = cipher->IVR;

    /* get ready to process first byte */
    b = 7;			/* start with top bit in byte */
    *outBuffer = 0;		/* and zero byte in outBuffer */

    /* now loop over all bits of input */
    for (j = 0; j < inputLen; j++) {
        msgbit = (*input >> b) & 01;	/* get next msg bit */
	prev = msgbit;			/* and save for shift register update */

        if (debuglevel) fprintf(stderr,"%s: deCFB1(%01X,%08X%08X%08X%08X) ", NAME, msgbit, L.l, L.r, R.l, R.r);
        if (debuglevel > 1) fprintf(stderr,"\n");

        /*  compute all rounds to encrypt current CFB1 buffer */
        k = 0;
        for (i = 0; i < ROUNDS; i++) {
            nR = add64(R, key->SK[k++]);		/* nR = R+SK(k) */
            f_out = f(nR, key->SK[k++]);		/* f = f(nR,SK(k+1)) */
            nR = add64(nR, key->SK[k++]);		/* nR = nR+SK(k+2) */
            R.l = L.l ^ f_out.l; R.r = L.r ^ f_out.r;	/* R = L XOR f */
            L = nR;					/* L = nR */
            if (debuglevel > 1) fprintf(stderr," L[%02d]=%08X%08X; R[%02d]=%08X%08X; f(SK(%02d))=%08X%08X\n", i+1, L.l, L.r, i+1, R.l, R.r, k-2, f_out.l, f_out.r);
        }
	/* undo last swap */
	L = R; R = nR;

	/* now process msgbit by getting stream key bit, XOR in and or to out */
	keybit = L.l >> 31;
	msgbit ^= keybit;
	*outBuffer |= (msgbit << b);

        if (debuglevel > 0) fprintf(stderr,"= %01X,%08X%08X%08X%08X\n", msgbit, L.l, L.r, R.l, R.r);

	/* and update the CFB1 shift register (input buffer L,R) */
	L.l = (L.l << 1) | (L.r >> 31); L.r = (L.r << 1) | (R.l >> 31);
	R.l = (R.l << 1) | (R.r >> 31); R.r = (R.r << 1) | prev;

	/* and update bit position counter */
	b--;
	/* and move to next input/output byte if necessary */
	if (b<0) { b = 7; input++; outBuffer++; *outBuffer = 0; }
    }

    /* save new IV value */
    cipher->IVL = L; cipher->IVR = R;
    return TRUE;
}


/*  LOKI97 methods */
/* ......................................................................... */
    
/*
 * f(A,B) = Sb(P(Sa(E(KP(A,hi(B))))),lo(B)) - complex non-linear round function
 */
static ULONG64 f (ULONG64 A, ULONG64 B)
{

    ULONG64	d, e, f;	/* intermediate values in f computation */
    register	s;		/* s-box output value */

    /*  Intermediate values in the computation are: */
    /*    d = KP(A,Br) */
    /*    e = P(Sa(d)) */
    /*    f = Sb(e,Bl) */

    /*  Compute d = KP(A,B), where KP is a keyed permutation used to  */
    /*     exchange corresponding bits in 32-bit words [Al,Ar]  */
    /*     based on the lower half of B (swap if B bit is 1) */
    /*     KP(A,B) = ((Al & ~Br)|(Ar & Br)) | ((Ar & ~Br)|(Al & Br)) */

    d.l = ((A.l & ~B.r) | (A.r & B.r));
    d.r = ((A.r & ~B.r) | (A.l & B.r));

    /*  Compute e = P(Sa(d)) */
    /*     mask out each group of 12 bits for E */
    /*     then compute first S-box column [S1,S2,S1,S2,S2,S1,S2,S1] */
    /*     permuting output through P (with extra shift to build full P) */

    s = S1[(d.l>>24 | d.r<<8) & 0x1FFF];  e.l  = P[s].l>>7;  e.r  = P[s].r>>7;
    s = S2[(d.l>>16)          &  0x7FF];  e.l |= P[s].l>>6;  e.r |= P[s].r>>6;
    s = S1[(d.l>> 8)          & 0x1FFF];  e.l |= P[s].l>>5;  e.r |= P[s].r>>5;
    s = S2[ d.l               &  0x7FF];  e.l |= P[s].l>>4;  e.r |= P[s].r>>4;
    s = S2[(d.r>>24 | d.l<<8) &  0x7FF];  e.l |= P[s].l>>3;  e.r |= P[s].r>>3;
    s = S1[(d.r>>16)          & 0x1FFF];  e.l |= P[s].l>>2;  e.r |= P[s].r>>2;
    s = S2[(d.r>> 8)          &  0x7FF];  e.l |= P[s].l>>1;  e.r |= P[s].r>>1;
    s = S1[ d.r               & 0x1FFF];  e.l |= P[s].l;     e.r |= P[s].r;

    /*  Compute f = Sb(e,B) */
    /*     where the second S-box column is [S2,S2,S1,S1,S2,S2,S1,S1] */
    /*     for each S, lower bits come from e, upper from upper half of B */

    f.l = S2[(((e.l>>24) & 0xFF) | ((B.l>>21) &  0x700))] << 24 |
          S2[(((e.l>>16) & 0xFF) | ((B.l>>18) &  0x700))] << 16 |
          S1[(((e.l>> 8) & 0xFF) | ((B.l>>13) & 0x1F00))] <<  8 |
          S1[(((e.l    ) & 0xFF) | ((B.l>> 8) & 0x1F00))];
    f.r = S2[(((e.r>>24) & 0xFF) | ((B.l>> 5) &  0x700))] << 24 |
          S2[(((e.r>>16) & 0xFF) | ((B.l>> 2) &  0x700))] << 16 |
          S1[(((e.r>> 8) & 0xFF) | ((B.l<< 3) & 0x1F00))] <<  8 |
          S1[(( e.r      & 0xFF) | ((B.l<< 8) & 0x1F00))];

    if (debuglevel > 3) fprintf(stderr,"%s: f(%08X%08X,%08X%08X) = %08X%08X\n", NAME, A.l, A.r, B.l, B.r, f.l, f.r);
    if (debuglevel > 4) fprintf(stderr,"%s:   d=%08X%08X; e=%08X%08X\n", NAME, d.l, d.r, e.l, e.r);

    return f;
}


/*  utility methods */
/* ......................................................................... */


/* add64(a,b) - fudge 64-bit addition of ULONG64's a and b */
/* thanks to Markku-Juhani Saarinen <mjos@ssh.fi> for the nice tips */
static ULONG64 add64(ULONG64 a, ULONG64 b)
{
    ULONG64		sum;		/* sum = a + b */

    sum.r = a.r + b.r;			/* add lower half */
    sum.l = a.l + b.l;			/* add upper half without carry */
    if (sum.r < b.r) sum.l++;		/* add carry if needed */

    return sum;				/* return resulting sum */
}


/* sub64(a,b) - fudge 64-bit subtraction of ULONG64's a and b */
/* thanks to Markku-Juhani Saarinen <mjos@ssh.fi> for the nice tips */
static ULONG64 sub64(ULONG64 a, ULONG64 b)
{
    ULONG64		diff;		/* diff = a + b */

    diff.r = a.r - b.r;			/* sub lower 32-bits */
    diff.l = a.l - b.l;			/* sub upper 32-bits */
    if (diff.r > a.r) diff.l--;		/* sub borrow if needed */

    return diff;			/* return resulting diff */
}


/* Returns a ULONG64 I constructed from a byte array. */
static ULONG64 byteToULONG64(BYTE *inp)
{
    ULONG64 I;
    I.l  = (*inp++ << 24);
    I.l |= (*inp++ << 16);
    I.l |= (*inp++ <<  8);
    I.l |= *inp++;
    I.r  = (*inp++ << 24);
    I.r |= (*inp++ << 16);
    I.r |= (*inp++ <<  8);
    I.r |= *inp++;
    return I;
}


/* Returns a byte array buf constructed by unpacking ULONG64 I. */
static BYTE *ULONG64ToBYTE(BYTE *buf, ULONG64 I)
{
    BYTE *sav = buf;
    *buf++ = (I.l >> 24);
    *buf++ = (I.l >> 16);
    *buf++ = (I.l >>  8);
    *buf++ = I.l;
    *buf++ = (I.r >> 24);
    *buf++ = (I.r >> 16);
    *buf++ = (I.r >>  8);
    *buf++ = I.r;
    return sav;
}


/* Returns a BYTE array from a string of hexadecimal digits. */
static BYTE *charToBYTE(BYTE *buf, char *hex, int len)
{
    int i = 0, j = 0;
    while (j < len) {
        buf[j++] = (BYTE)((fromHex(hex[i++])<<4) | fromHex(hex[i++]));
    }
    return buf;
}


/* Returns a ULONG64 I constructed from a string of hexadecimal digits. */
static ULONG64 charToULONG64(char *hex)
{
    ULONG64 I;
    I.l  = fromHex(*hex++) << 28;
    I.l |= fromHex(*hex++) << 24;
    I.l |= fromHex(*hex++) << 20;
    I.l |= fromHex(*hex++) << 16;
    I.l |= fromHex(*hex++) << 12;
    I.l |= fromHex(*hex++) <<  8;
    I.l |= fromHex(*hex++) <<  4;
    I.l |= fromHex(*hex++);
    I.r  = fromHex(*hex++) << 28;
    I.r |= fromHex(*hex++) << 24;
    I.r |= fromHex(*hex++) << 20;
    I.r |= fromHex(*hex++) << 16;
    I.r |= fromHex(*hex++) << 12;
    I.r |= fromHex(*hex++) <<  8;
    I.r |= fromHex(*hex++) <<  4;
    I.r |= fromHex(*hex++);
    return I;
}


/* Returns number from 0 to 15 corresponding to hex digit ch */
static int fromHex (char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    else
        return 0;
}


/* puthex(out, len, f) - display a len byte value out in hex to file f */
static int puthex(BYTE *out, int len, FILE *f)
{
    int i;
    for(i=0;i<len;i++){
        fprintf(f, "%02X",*out++ & 0xff);
    }
    fputc(' ', f);
}



/* ......................................................................... */
/*
 * self_test() - Encryption/decryption test using the standard single triple 
 *    returns true or error code
 */
int self_test()
{
    int enok = TRUE, deok = TRUE;
    char *hexkey = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    char *hexcipher = "75080E359F10FE640144B35C57128DAD";
    char *hexIV = "00000000000000000000000000000000";
    BYTE	plain[BLOCK_SIZE] =
			{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    BYTE	etemp[BLOCK_SIZE], dtemp[BLOCK_SIZE], cipher[BLOCK_SIZE];
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	loki97_cipher;		/* AES cipherInstance */
    int	i, st;

    /* construct desired cipher block */
    charToBYTE(cipher,hexcipher,sizeof(cipher));

    /* Init LOKI97 cipher in ECB mode */
    st = cipherInit(&loki97_cipher, MODE_ECB, hexIV); if (st != TRUE) return st;

    /* test encrypt */
    st = makeKey(&enc_key, DIR_ENCRYPT, 256, hexkey); if (st != TRUE) return st;
    fprintf(stderr,"Plaintext is: ");
    puthex(plain,16,stderr); fprintf(stderr,"\n");

    st = blockEncrypt(&loki97_cipher, &enc_key, plain, sizeof(plain)*8, etemp);
    if (st != TRUE) return st;
    if (memcmp(etemp, cipher, sizeof(etemp)) != 0) enok = FALSE;
    fprintf(stderr,"Test encrypt: "); puthex(etemp,16,stderr);
    fprintf(stderr," %s\n", (enok?"GOOD" : "FAILED"));

    /* test decrypt */
    st = makeKey(&dec_key, DIR_DECRYPT, 256, hexkey); if (st != TRUE) return st;
    st = blockDecrypt(&loki97_cipher, &dec_key, etemp, sizeof(etemp)*8, dtemp);
    if (st != TRUE) return st;
    if (memcmp(dtemp, plain, sizeof(dtemp)) != 0) deok = FALSE;
    fprintf(stderr,"Test decrypt: "); puthex(dtemp,16,stderr);
    fprintf(stderr," %s\n", (deok?"GOOD" : "FAILED"));

    return (enok && deok);	/* return TRUE only if both en & decrypt ok */
}


/* ========================================================================
 * ======================== START OF BBC.C ================================
 * ======================================================================== 
 * This is a big block cipher (256K blocks) using three PRNGs, two
 * substitution tables, cipher-text feedback, and transposition.
 * 
 * Author Peter K. Boucher <boucher@csl.sri.com>
 *
 * Copyright 1993 Peter K. Boucher
 * Permission to use, copy, modify, and distribute this software
 * for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies.
 * ======================================================================== */

#include <stdio.h>

#define BLOCKSIZE	262144
#define BYTESIZE	256

/* ========== Coefficients For Irreducible Trinomials For PRNGs =========== */
#define DEG_A1		1289		/* X**1289 + X**242 + 1 */
#define DEG_B1		242
#define DEG_A2		1223		/* X**1223 + X**588 + 1 */
#define DEG_B2		588
#define DEG_A3		431		/* X**431 + X**200 + 1 */
#define DEG_B3		200

/* ========== PRNG State Data ============================================= */
static  long		state1[DEG_A1], state2[DEG_A2], state3[DEG_A3];
static  long		*fptr1,		*fptr2,		*fptr3;
static  long		*rptr1,		*rptr2,		*rptr3;
static  long		*end_ptr1,	*end_ptr2,	*end_ptr3;

/* ========== Local Subroutines =========================================== */
unsigned char crnd1();
void initialize_crnd1();
unsigned char crnd2();
void initialize_crnd2();
unsigned int rnd();
void initialize_rnd();
void init_repl_tab();
void init_sub_tab();
void transpose_buf();
void refresh_repl_tab();
void refresh_sub_tab();

/* 
 * ========================================================================
 * ========== Encryption Subroutine =======================================
 *
 * int bbc_crypt(infile, outfile, key1, key2, key3, ENCRYPT)
 *     FILE *infile, *outfile;
 *     long key1, key2, key3;
 *     int ENCRYPT;
 *
 * This subroutine is the encryption engine.  The routine reads blocks of
 * input that are 262144 bytes in size.  For each 256K block:
 *
 *   a) Each byte of the block is combined with the output of a PRNG,
 *      using a substitution table, and using cipher-text feedback, in
 *      ASCENDING order, so that each output depends on all PREVIOUS
 *      input bytes of THE ENTIRE MESSAGE.
 *
 *   b) Each byte of the block is combined with the output of a second
 *      PRNG, using a second substitution table, and using cipher-text
 *      feedback, in DESCENDING order, so that each output depends on
 *      all SUBSEQUENT inputs bytes of THIS BLOCK (and again, on all
 *      output bytes in all previous blocks).
 *
 *   c) The block is "shuffled" using a transposition algorithm posted
 *      to USENET by Carl Ellison (with a modified interface).
 *
 * Decryption reverses the process:  a) transposition, b) descending
 * PRNG combination and substitution, and c) ascending PRNG combination
 * and substitution.  Note: no mechanized clear-text recognizer will
 * work until the first two decryption steps are completed on an entire
 * block, and the final step is completed on at least a few bytes.
 *
 * A third PRNG is used to randomize the substitution tables, and to
 * perform the transpositions.  The key to this encryption algorithm
 * consists of three 32-bit seeds for the three PRNGs.  Thus, the
 * total key size is 96 bits.  Brute force attacks are hindered by
 * the large block size and the large key size.  Cryptanalysis is
 * hindered by the large block size, with every byte in the output
 * block depending on every byte in the input block (and all
 * previous input blocks), and also by the transposition.  The
 * cryptographic strength of the PRNGs is crucial to the strength
 * of this system.
 *
 * ======================================================================== */
int bbc_crypt(infile, outfile, key1, key2, key3, ENCRYPT)
FILE *infile, *outfile;
long key1, key2, key3;
int ENCRYPT;
{
    register int i, len;
    register unsigned int cipher_text1, cipher_text2, feedback;
    static unsigned char io_buf[BLOCKSIZE];
    static unsigned char e_sub_table_1a[BYTESIZE];
    static unsigned char e_sub_table_1b[BYTESIZE];
    static unsigned char e_sub_table_1c[BYTESIZE];
    static unsigned char d_sub_table_1a[BYTESIZE];
    static unsigned char d_sub_table_1b[BYTESIZE];
    static unsigned char d_sub_table_1c[BYTESIZE];
    static unsigned char e_sub_table_2a[BYTESIZE];
    static unsigned char e_sub_table_2b[BYTESIZE];
    static unsigned char e_sub_table_2c[BYTESIZE];
    static unsigned char d_sub_table_2a[BYTESIZE];
    static unsigned char d_sub_table_2b[BYTESIZE];
    static unsigned char d_sub_table_2c[BYTESIZE];
    static unsigned char repl_table_1a[BYTESIZE];
    static unsigned char repl_table_1b[BYTESIZE];
    static unsigned char repl_table_2a[BYTESIZE];
    static unsigned char repl_table_2b[BYTESIZE];


    initialize_crnd1(key1);
    initialize_crnd2(key2);
    initialize_rnd(key3);
    init_sub_tab(e_sub_table_1a, d_sub_table_1a);
    init_sub_tab(e_sub_table_1b, d_sub_table_1b);
    init_sub_tab(e_sub_table_1c, d_sub_table_1c);
    init_sub_tab(e_sub_table_2a, d_sub_table_2a);
    init_sub_tab(e_sub_table_2b, d_sub_table_2b);
    init_sub_tab(e_sub_table_2c, d_sub_table_2c);
    init_repl_tab(repl_table_1a);
    init_repl_tab(repl_table_1b);
    init_repl_tab(repl_table_2a);
    init_repl_tab(repl_table_2b);
    cipher_text1 = crnd1();
    cipher_text2 = crnd2();

    while ((len = fread(io_buf,1,BLOCKSIZE,infile)) > 0) {
	fprintf(stderr, ".");
	refresh_sub_tab(e_sub_table_1a, d_sub_table_1a);
	refresh_sub_tab(e_sub_table_1b, d_sub_table_1b);
	refresh_sub_tab(e_sub_table_1c, d_sub_table_1c);
	refresh_sub_tab(e_sub_table_2a, d_sub_table_2a);
	refresh_sub_tab(e_sub_table_2b, d_sub_table_2b);
	refresh_sub_tab(e_sub_table_2c, d_sub_table_2c);
	refresh_repl_tab(repl_table_1a);
	refresh_repl_tab(repl_table_1b);
	refresh_repl_tab(repl_table_2a);
	refresh_repl_tab(repl_table_2b);
	if (ENCRYPT) {
	    for (i=0; i<len; i++) {
		feedback = cipher_text1;
		cipher_text1 = io_buf[i] =
		  e_sub_table_1a[repl_table_1a[crnd1()]^
		                 e_sub_table_1b[e_sub_table_1c[io_buf[i]]^
		                                repl_table_1b[feedback]]];
	    } 
	    for (i=len-1; i>=0; i--) {
		feedback = cipher_text2;
		cipher_text2 = io_buf[i] =
		  e_sub_table_2a[repl_table_2a[crnd2()]^
		                 e_sub_table_2b[e_sub_table_2c[io_buf[i]]^
		                                repl_table_2b[feedback]]];
	    }
	    transpose_buf(io_buf, len);
	} else { /* DECRYPT reverses the steps. */
	    transpose_buf(io_buf, len);
	    for (i=len-1; i>=0; i--) {
		feedback = cipher_text2;
		cipher_text2 = io_buf[i];
		io_buf[i] =
		  d_sub_table_2c[repl_table_2b[feedback]^
		                 d_sub_table_2b[d_sub_table_2a[io_buf[i]]^
		                                repl_table_2a[crnd2()]]];
	    }
	    for (i=0; i<len; i++) {
		feedback = cipher_text1;
		cipher_text1 = io_buf[i];
		io_buf[i] =
		  d_sub_table_1c[repl_table_1b[feedback]^
		                 d_sub_table_1b[d_sub_table_1a[io_buf[i]]^
		                                repl_table_1a[crnd1()]]];
	    }
	}
	if (fwrite(io_buf, 1, len, outfile) != len) {
	    fprintf(stderr, "Error writing output.  Abort.\n");
	    exit(1);
	}
    }
    fprintf(stderr, "\n");
    return(0);
}

/* 
 * ========================================================================
 * ========== Character PRNG 1 ============================================
 *
 * This subroutine returns a pseudo-random character.
 *
 * It uses more than 5160 bytes of state information, and bases its
 * randomness on an irreducible trinomial.
 *
 * X**1289 + X**242 + 1 
 *
 * ======================================================================== */
unsigned char crnd1()
{
	register unsigned long	i;
	register long	*frnt=fptr1, *rear=rptr1;

	i = *frnt + *rear;
	*frnt = i;
	if(  ++frnt  >=  end_ptr1  )  {
	    frnt = state1;
	    ++rear;
	} else  {
	    if(  ++rear  >=  end_ptr1  )  rear = state1;
	}
	fptr1=frnt;
	rptr1=rear;
	return( (unsigned char)(i >> 6) );
}

/* 
 * ========================================================================
 * ========== Character PRNG 1 Initialization =============================
 *
 * This subroutine creates an initial state for crnd1.
 *
 * ======================================================================== */
void initialize_crnd1( seed )
    register unsigned long seed;

{
	register unsigned int	i;
	register unsigned int	num_rnds;

	rptr1 = state1;
	end_ptr1 = &state1[DEG_A1];
	fptr1 = &state1[DEG_B1];
	state1[ 0 ] = seed;
	for( i = 1; i < DEG_A1; i++ )  {
	    seed = state1[i] = 1103515245*seed + 12345;
	}
	num_rnds = (10*DEG_A1) + (seed%DEG_A1);
	for( i = 0; i < num_rnds; i++ )  crnd1();
}

/* 
 * ========================================================================
 * ========== Character PRNG 2 ============================================
 *
 * This subroutine returns a pseudo-random character.
 *
 * It uses more than 4895 bytes of state information, and bases its
 * randomness on an irreducible trinomial.
 *
 * X**1223 + X**588 + 1
 *
 * ======================================================================== */
unsigned char crnd2()
{
	register unsigned long	i;
	register long	*frnt=fptr2, *rear=rptr2;

	i = *frnt + *rear;
	*frnt = i;
	if(  ++frnt  >=  end_ptr2  )  {
	    frnt = state2;
	    ++rear;
	} else  {
	    if(  ++rear  >=  end_ptr2  )  rear = state2;
	}
	fptr2=frnt;
	rptr2=rear;
	return( (unsigned char)(i >> 23) );
}

/* 
 * ========================================================================
 * ========== Character PRNG 2 Initialization =============================
 *
 * This subroutine creates an initial state for crnd2.
 *
 * ======================================================================== */
void initialize_crnd2( seed )
    register unsigned long seed;

{
	register unsigned int	i;
	register unsigned int	num_rnds;

	rptr2 = state2;
	end_ptr2 = &state2[DEG_A2];
	fptr2 = &state2[DEG_B2];
	state2[ 0 ] = seed;
	for( i = 1; i < DEG_A2; i++ )  {
	    seed = state2[i] = 1103515245*seed + 12345;
	}
	num_rnds = (10*DEG_A2) + (seed%DEG_A2);
	for( i = 0; i < num_rnds; i++ )  crnd2();
}

/* 
 * ========================================================================
 * ========== Integer PRNG ================================================
 *
 * This subroutine returns a pseudo-random unsigned integer.
 *
 * It uses more than 1725 bytes of state information, and bases its
 * randomness on an irreducible trinomial.
 *
 * X**431 + X**200 + 1
 *
 * ======================================================================== */
unsigned int rnd()
{
	register unsigned long	i;
	register long	*frnt=fptr3, *rear=rptr3;

	i = *frnt + *rear;
	*frnt = i;
	if(  ++frnt  >=  end_ptr3  )  {
	    frnt = state3;
	    ++rear;
	} else  {
	    if(  ++rear  >=  end_ptr3  )  rear = state3;
	}
	fptr3=frnt;
	rptr3=rear;
	return( (unsigned int)((i >> 10) | (i << 22)) );
}

/* 
 * ========================================================================
 * ========== Integer PRNG Initialization =================================
 *
 * This subroutine creates an initial state for rnd.
 *
 * ======================================================================== */
void initialize_rnd( seed )
    register unsigned long seed;

{
	register unsigned int	i;
	register unsigned int	num_rnds;

	rptr3 = state3;
	end_ptr3 = &state3[DEG_A3];
	fptr3 = &state3[DEG_B3];
	state3[ 0 ] = seed;
	for( i = 1; i < DEG_A3; i++ )  {
	    seed = state3[i] = 1103515245*seed + 12345;
	}
	num_rnds = (10*DEG_A3) + (seed%DEG_A3);
	for( i = 0; i < num_rnds; i++ )  rnd();
}

/* 
 * ========================================================================
 * ========== Character Replacement Table Initialization ==================
 *
 * This subroutine fills an array with the values 0 - 255 in pseudo-
 * random order.
 *
 * ======================================================================== */
void init_repl_tab(repl_tab)
register unsigned char *repl_tab;
{
    register unsigned int i, j, k;
    unsigned char tmp[BYTESIZE];

    for (i=0; i < BYTESIZE; i++) {
	tmp[i] = (unsigned char)i;
    }
    while (i > 1) {
	j = rnd() % i;
	repl_tab[i-1] = tmp[j];
	for (k=j; k<(i-1); k++) {
	    tmp[k] = tmp[k+1];
	}
	i--;
    }
    repl_tab[0] = tmp[0];
}

/* 
 * ========================================================================
 * ========== Character Substitution Table Pair Initialization ============
 *
 * This subroutine creates a pair of pseudo-random substitution tables.
 *
 * ======================================================================== */
void init_sub_tab(estab, dstab)
register unsigned char *estab, *dstab;
{
    register unsigned int i;
    init_repl_tab(estab);
    for (i=0; i< BYTESIZE; i++) {
	dstab[estab[i]] = (unsigned char)i;
    }
}

/* 
 * ========================================================================
 * ========== Buffer Transposition Subroutine =============================
 *
 * This subroutine transposes the characters of a buffer in pseudo-
 * random order.
 *
 * ======================================================================== */
void transpose_buf(buf, len)
register unsigned char *buf;
register unsigned int len;
{
    register unsigned char tmp;
    register unsigned int i, pos;
    static unsigned int perm[BLOCKSIZE];

    if (len > BLOCKSIZE) {
	fprintf(stderr, "Internal error:  invalid buffer size (%d).\n", len);
	exit(1);
    }
    for (i = 0; i < len; i++)
      perm[i] = i;
    
#define swap(A,B)  tmp = A; A = B; B = tmp;

    while (len > 1)
      {
	pos = 1 + rnd() % (len - 1);
	swap( buf[perm[0]], buf[perm[pos]] );

	perm[0]   = perm[(pos == len - 2) ? len - 1 : len - 2];
	perm[pos] = perm[len - 1];
	len -= 2;
      }
}

/* 
 * ========================================================================
 * ========== Character Replacement Table Reinitialization ================
 *
 * This subroutine re-randomizes an array with the values 0 - 255 in
 * pseudo-random order.
 *
 * ======================================================================== */
void refresh_repl_tab(repl_tab)
register unsigned char *repl_tab;
{
    transpose_buf(repl_tab, BYTESIZE);
}

/* 
 * ========================================================================
 * ========== Character Substitution Table Pair Reinitialization ==========
 *
 * This subroutine re-randomizes a pair of substitution tables.
 *
 * ======================================================================== */
void refresh_sub_tab(estab, dstab)
register unsigned char *estab, *dstab;
{
    register unsigned int i;
    refresh_repl_tab(estab);
    for (i=0; i< BYTESIZE; i++) {
	dstab[estab[i]] = (unsigned char)i;
    }
}

/* ========================================================================
 * ========================= END OF BBC.C =================================
 * ======================================================================== */

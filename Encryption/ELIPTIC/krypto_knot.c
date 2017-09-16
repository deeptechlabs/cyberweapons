/****** krypto_knot.c *****/
/********************************************************************************
*										*
*	The purpose of this file is to tie together all the subroutines from	*
*  the elliptic curve optimal normal basis suite to create a key hiding system.	*
*  The actual compression and encoding should be performed by standard 		*
*  algorithms such as arith-n (compression book) and blowfish (Dr. Dobbs's	*
*  Journal or Applied Cryptography.  The complete system would then violate ITAR*
*  and not be accessable, so you'll have to hack that yourself.			*
*										*
********************************************************************************/

#include <stdio.h>
#ifdef MACHTEN
#include <strings.h>
#else
#include <string.h>
#endif
#include <malloc.h>
#include "bigint.h"
#include "eliptic.h"
#include "eliptic_keys.h"
#include "support.h"
#include "krypto_knot.h"

extern void null(BIGINT*);
extern void copy(BIGINT*, BIGINT*);
extern void fofx(BIGINT*, CURVE*, BIGINT*);
extern int gf_quadradic(BIGINT*, BIGINT*, BIGINT*);
extern void one(BIGINT*);
extern void Mother(unsigned long*);
extern void esum(POINT*, POINT*, POINT*, CURVE*);
extern void esub(POINT*, POINT*, POINT*, CURVE*);
extern void elptic_mul(BIGINT*, POINT*, POINT*, CURVE*);
extern void public_key_gen(BIGINT*, PUBKEY*, INDEX);
extern int restore_pub_key( char*, PUBKEY*);
extern void print_pubkey( PUBKEY*);
extern void big_print(char*, BIGINT*);

extern unsigned long random_seed;

/*   encrypt a session key.  Enter with given session key to hide, public key
to hide it in, and storage block for result.  It is a waste of space to use a
PUBKEY for this, too bad.

session == pointer to key to be hidden
pk == pointer to public key block to use
ek == pointer to resultant key block.  ek->p holds kP, ek->q holds S+kQ
*/

void elptic_encrypt(session, pk, ek)
BIGINT * session;
PUBKEY * pk, * ek;
{
	INDEX	i;
	BIGINT	k, f, y[2];
	POINT	s, t;

/*  encode session key onto a random point using this public key.  */

	null(&k);
	Mother(&random_seed);
	copy(session, &k);
	k.b[STRTPOS] = random_seed & UPRMASK;

/*  note that this assumes session key < NUMBITS and that STRTPOS ELEMENT is free
to be clobbered.  For all reasonable encoding schemes this shouldn't be a problem.
*/

	fofx( &k, &pk->crv, &f);
	while (gf_quadradic(&k, &f, y)) {
	   k.b[STRTPOS]++;
	   fofx(&k, &pk->crv, &f);
	}
	copy( &k, &s.x);
	copy( &y[1],&s.y);	/*  use 1 just to be different, why not eh?  */

/*  next generate a random multiplier k  */

	null(&k);
	SUMLOOP(i) {
	   Mother(&random_seed);
	   k.b[i] = random_seed;
	}
	k.b[STRTPOS] &= UPRMASK;

/*  do 2 multiplies, kp and kq  */

	elptic_mul(&k, &pk->p, &ek->p, &pk->crv);
	elptic_mul(&k, &pk->q, &t, &pk->crv);

/*  add s to kQ as final step  */

	esum(&s, &t, &ek->q, &pk->crv);
	ek->crv.form = pk->crv.form;
	copy( &pk->crv.a2, &ek->crv.a2);
	copy( &pk->crv.a6, &ek->crv.a6);
}

/*  decrypt session key from public and encrypted key.
	returns 0 if successful, -1 on failure (wrong pass phrase).
*/

int elptic_decrypt(session, pk, ek)
BIGINT * session;
PUBKEY * pk, * ek;
{
	INDEX	i;
	BIGINT	skey;
	POINT	check, t, s;

/*  first ensure you can generate secret key.  */

	public_key_gen(&skey, pk, 0);
	elptic_mul(&skey, &pk->p, &check, &pk->crv);
	SUMLOOP(i) {
	   if (check.x.b[i] != pk->q.x.b[i]) {
	      printf("Invalid pass phrase.\n");
	      return(-1);
	   }
	}

/*  next compute T = aR and subtract from R' to get S  */

	elptic_mul(&skey, &ek->p, &t, &pk->crv);
	esub(&ek->q, &t, &s, &pk->crv);

/*  clear out encoding garbage and return session key */

	copy( &s.x, session);
	session->b[STRTPOS] = 0;
	return(0);
}

/*  random hash curve and point for symmetric system.  Should probably choose
    something more secure than purely random.
*/

CURVE sym_hash_crv={0,{0,0,0,0,0,0,0,0},
	{0,0,0,0x000781a4,0x86230aac,0x994e18e8,0xd9f5d7ba,0xb9535103}};
POINT sym_hash_pnt={
	{0,0,0,0x00055db3,0xe5950234,0xc9436d57,0x08ab23de,0xa2f84583},
	{0,0,0,0x0004971c,0x14515ead,0xe09d9ebe,0x72649fc5,0x24607f32}};

/*  Symmetric cipher based on elliptic curves.  There are many ways to pick the
encryptor points r which are added to plain text embedded data to create cipher 
text.  The particular method chosen here is quick, and should be reasonably 
secure.  If the attacker knows ciphertext, plaintext and state of random number
generator, then r can be found and the key recovered.  It's probably a good 
idea to reset the random number generator by wiping out the data file once 
in a while to foil this attack.  By never storing plaintext on disk the 
possibility of attack becomes even more remote.

Enter with arguments:

	key	- same for encipher and decipher

	length	- incoming count of plaintext data in bytes or
			cipher text data in ELEMENTS.

	plain	- plaintext data storage area

	crypt	- ciphertext data storage area

	direction 0 for encryption   plain->crypt
		  1 for decryption   crypt->plain

Encrypted text is stored as compressed points.  One bit of y/x in msb and x in 
lower bits.  Returns count in ELEMENTS of length of data for encryption and
count in bytes for decryption.
*/

ELEMENT elptic_cipher(key, length, plain, crypt, direction)
BIGINT * key;
ELEMENT length, * crypt;
char * plain;
INDEX direction;
{
	POINT	r[3];
	CURVE	ek;
	POINT	pi, qi;
	BIGINT	xinv, qbit, f, y[2];
	INDEX	i,j,k,keycount;
	long	counter;
	ELEMENT	crypt_count, keymask;

/*  step 1: create a curve based on key */

	elptic_mul( key, &sym_hash_pnt, &pi, &sym_hash_crv);
	copy( &pi.x, &ek.a6);
	ek.form = 0;
	null(&ek.a2);

/*  step 2: create zeroth encryptor point on curve ek usng key and hash point.  
		Use key for bottom half of point and sym_hash_pnt.x as top.  
		Use last bit of key to determine which root of y to use.   */

	for( i=0; i<3; i++) {
	   null( &r[i].x);
	   null( &r[i].y);
	}

	for( i=0; i<KEY_LENGTH; i++) r[0].x.b[LONGPOS-i] = key->b[LONGPOS-i];
	for( i=STRTPOS; i<MAXLONG-KEY_LENGTH; i++) 
			r[0].x.b[i] = sym_hash_pnt.x.b[i];
	fofx( &r[0].x, &ek, &f);
	while( gf_quadradic( &r[0].x, &f, &y[0])) {
	   r[0].x.b[LONGPOS-KEY_LENGTH]++;
	   fofx( &r[0].x, &ek, &f);
	}
	if (key->b[LONGPOS] & 1) copy( &y[0], &r[0].y);
	else copy( &y[1], &r[0].y);

/*  step 3: use key based curve to put message blocks onto points.  Use key
		to determine next encryptor point.  */

	edbl( &r[0], &r[1], &ek);
	i = 1;
	keymask = 1;
	keycount = 0;
	crypt_count = 0;

/*  i tracks encryptor point sequence and is member of set {0, 1, 2}
    keymask tracks which bit of key within ELEMENT number
    kecount.  crypt_count counts bytes if decrypting and ELEMENTs if encrypting.
*/

	counter = length;
	while( counter>0) {
	   null( &pi.x);
	   null( &qi.x);
	   if (!direction) {       /*  0 == encrypt bytes to elliptic points  */

/*  create KEY_LENGTH block of data as bottom of next point to encrypt  */

	      for( j=KEY_LENGTH; j>0; j--) {
		if (counter > 0) {
		   pi.x.b[MAXLONG - j] = *((ELEMENT*)plain);
		   plain += sizeof(ELEMENT);
		   counter -= sizeof(ELEMENT);
		} 
	      }

/*  attach random seed data to top of point to help scatter data across as 
	large a universe as possible.  */

	      for( j=STRTPOS; j<MAXLONG - KEY_LENGTH; j++) {
		Mother( &random_seed);
		pi.x.b[j] = random_seed;
	      }
	      pi.x.b[STRTPOS] &= UPRMASK;

/*  embed plain text onto cipher curve by finding "local" point to random location */

	      fofx( &pi.x, &ek, &f);
	      while( gf_quadradic( &pi.x, &f, &y[0])) {
		pi.x.b[LONGPOS-KEY_LENGTH]++;
		fofx( &pi.x, &ek, &f);
	      }
	      copy( &y[0], &pi.y);

/*  encrypt data by adding key based point to random point over key based curve */

	      esum( &pi, &r[i], &qi, &ek);

/*  compress result point for storage  */

	      opt_inv( &qi.x, &xinv);
	      opt_mul( &qi.y, &xinv, &qbit);
	      if ( qbit.b[LONGPOS] & 1L) qi.x.b[STRTPOS] |= SUBMASK;
	      SUMLOOP (j) *crypt++ = qi.x.b[j];
	      crypt_count += (MAXLONG - STRTPOS);

	   } else {	/*  decrypt using same key  */

/*  grab the data, convert back to BIGINT from compressed  */

	      SUMLOOP(j) qi.x.b[j] = *crypt++;
	      counter -= MAXLONG - STRTPOS;
	      if ( qi.x.b[STRTPOS] & SUBMASK) {
		k = 1;
		qi.x.b[STRTPOS] &= UPRMASK;
	      } else
		k = 0;

/*  create y value  */

	      fofx( &qi.x, &ek, &f);
	      if (gf_quadradic( &qi.x, &f, &y[0])) {
		printf("Cipher point not on curve. \n");
		printf("Check data and key. \n");
		return(crypt_count);
	      }
	      copy( &y[k], &qi.y);

/*  decrypt data by subtracting key based point cipher point over key based curve */

	      esub( &qi, &r[i], &pi, &ek);

/*  copy only useful data into result block, throw random stuff away  */

	      for ( j=KEY_LENGTH; j>0; j--) {
		*((ELEMENT*)plain) = pi.x.b[MAXLONG - j];
		plain += sizeof(ELEMENT);
		crypt_count += sizeof(ELEMENT);
	      }
	   }

/*  compute next encryptor point from key and previous points.  */

	   j = i;
	   k = j - 1;
	   if (k < 0) k += 3;
	   i = (i + 1) % 3;
	   keymask <<= 1;
	   if (!keymask) {
	      keymask = 1;
	      keycount = (keycount + 1) % KEY_LENGTH;
	   }
	   if (key->b[LONGPOS - keycount] & keymask) esum( &r[j], &r[k], &r[i], &ek);
	   else edbl( &r[j], &r[i], &ek);
	}
	return(crypt_count);
}

void main()
{
        char    file[256];
	BIGINT	session_key, recovered_key, secret_key;
	PUBKEY	public_key, hidden_key;
	ELEMENT * cipher_array;
	char	* plain_array, * out_array;
	INDEX	i, length, out_length;
	POINT	hpnt;
	CURVE	hcurv;

	if((cipher_array = (ELEMENT *)malloc(sizeof(ELEMENT) * 16383))
		== NULL)
	    return;
	if((plain_array = (char *)malloc(sizeof(ELEMENT) * 65535))
		== NULL)
	    return;
	if((out_array = (char *)malloc(sizeof(ELEMENT) * 65535))
		== NULL)
	    return;
	    
        init_opt_math();
        init_rand();

/*  low level tests for changes at low level.  */

/*	get_curve( "hash.curve", &hcurv, &hpnt);
	opt_inv(&hpnt.x, &session_key);
	opt_mul(&session_key, &hpnt.x, &recovered_key);
	big_print("x = ",&hpnt.x);
	big_print("1/x = ", &session_key);
	big_print("x/x = ", &recovered_key);
	exit(0);
*/
/*  for this test, assume you have already generated a public key (and remember
the pass phrase!).  Read in key file from disk.  */

/*
        printf("input file name for previous key: ");
        scanf("%s",&file);
        (void)restore_pub_key(file, &public_key);
*/
	public_key_gen(&secret_key, &public_key, 1);
	print_pubkey(&public_key);
	big_print("secret key: ", &secret_key);

/*  generate a session key...  */

	printf("Generating session key and encryping it...\n");
	SUMLOOP(i) {
	   Mother(&random_seed);
	   session_key.b[i] = random_seed;
	}
	elptic_encrypt(&session_key, &public_key, &hidden_key);
	strcpy(hidden_key.name, public_key.name);
	strcpy(hidden_key.address, public_key.address);
	print_pubkey(&hidden_key);
	big_print("session_key: ",&session_key);
	elptic_decrypt(&recovered_key, &public_key, &hidden_key);
	big_print("recovered key: ",&recovered_key);

/*  test symmetric key cipher.  Use debugger for the moment.  */

	secret_key.b[LONGPOS-1] = 0x54484953;
	secret_key.b[LONGPOS] = 0x49532041;
	sprintf(plain_array , "A simple test of elliptic curves for use as a symmetric cipher.");
	length = strlen(plain_array);
	i = elptic_cipher( &secret_key, length, plain_array, cipher_array, 0);
	out_length = elptic_cipher(&secret_key, i, out_array, cipher_array, 1);
	printf("Output array is: \"%s\"\n",out_array);
	close_rand();
}
}

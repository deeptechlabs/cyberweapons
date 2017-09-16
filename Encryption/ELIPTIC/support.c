/******   support.c   *****/
/*  Simple support functions for elliptic curve data manipulation  */

#include <stdio.h>
/* Borland C++ needs stdlib to resolve exit(), and it's a good idea in general */
#include <stdlib.h>
#ifdef MACHTEN
#  include <strings.h>
#else
#  include <string.h>
#endif
#include "bigint.h"
#include "eliptic.h"
#include "eliptic_keys.h"
#include "support.h"

extern void init_opt_math();
extern gf_quadradic( BIGINT*, BIGINT*, BIGINT*);
extern void fofx( BIGINT*, CURVE*, BIGINT*);
extern void copy( BIGINT*, BIGINT*);
extern void null( BIGINT*);
extern void elptic_mul(BIGINT*, POINT*, POINT*, CURVE*);
extern void opt_inv(BIGINT*, BIGINT*);
extern void edbl(POINT*, POINT*, CURVE*);
extern void esum(POINT*, POINT*, POINT*, CURVE*);
extern void esub(POINT*, POINT*, POINT*, CURVE*);
extern void one( BIGINT*);
extern ELEMENT bit_table[WORDSIZE];

/*  random seed is accessable to everyone, not best way, but functional.  */

unsigned long random_seed;

/*  below is from Mother code, till end of mother.  Above is all my fault.  */

#include <string.h>

static short mother1[10];
static short mother2[10];
static short mStart=1;

#define m16Long 65536L                          /* 2^16 */
#define m16Mask 0xFFFF          /* mask for lower 16 bits */
#define m15Mask 0x7FFF                  /* mask for lower 15 bits */
#define m31Mask 0x7FFFFFFF     /* mask for 31 bits */
#define m32Double  4294967295.0  /* 2^32-1 */

/* Mother **************************************************************
|       George Marsaglia's The mother of all random number generators
|               producing uniformly distributed pseudo random 32 bit values with
|               period about 2^250.
|
|       The arrays mother1 and mother2 store carry values in their
|               first element, and random 16 bit numbers in elements 1 to 8.
|               These random numbers are moved to elements 2 to 9 and a new
|               carry and number are generated and placed in elements 0 and 1.
|       The arrays mother1 and mother2 are filled with random 16 bit values
|               on first call of Mother by another generator.  mStart is the switch.
|
|       Returns:
|       A 32 bit random number is obtained by combining the output of the
|               two generators and returned in *pSeed.  It is also scaled by
|               2^32-1 and returned as a double between 0 and 1
|
|       SEED:
|       The inital value of *pSeed may be any long value
|
|       Bob Wheeler 8/8/94
|
|	removed double return since I don't need it.
*/


void Mother(pSeed)
unsigned long * pSeed;
{
        unsigned long  number,
                       number1,
                       number2;
        short          n,
                       *p;
        unsigned short sNumber;

                /* Initialize motheri with 9 random values the first time */
        if (mStart) {
                sNumber= *pSeed&m16Mask;   /* The low 16 bits */
                number= *pSeed&m31Mask;   /* Only want 31 bits */

                p=mother1;
                for (n=18;n--;) {
                        number=30903*sNumber+(number>>16);   
				/* One line multiply-with-cary */
                        *p++=sNumber=number&m16Mask;
                        if (n==9)
                                p=mother2;
                }
                /* make cary 15 bits */
                mother1[0]&=m15Mask;
                mother2[0]&=m15Mask;
                mStart=0;
        }

                /* Move elements 1 to 8 to 2 to 9 */
        memmove(mother1+2,mother1+1,8*sizeof(short));
        memmove(mother2+2,mother2+1,8*sizeof(short));

                /* Put the carry values in numberi */
        number1=mother1[0];
        number2=mother2[0];

                /* Form the linear combinations */

number1+=1941*mother1[2]+1860*mother1[3]+1812*mother1[4]+1776*mother1[5]+
         1492*mother1[6]+1215*mother1[7]+1066*mother1[8]+12013*mother1[9];

number2+=1111*mother2[2]+2222*mother2[3]+3333*mother2[4]+4444*mother2[5]+
         5555*mother2[6]+6666*mother2[7]+7777*mother2[8]+9272*mother2[9];

                /* Save the high bits of numberi as the new carry */
        mother1[0]=number1/m16Long;
        mother2[0]=number2/m16Long;
                /* Put the low bits of numberi into motheri[1] */
        mother1[1]=m16Mask&number1;
        mother2[1]=m16Mask&number2;

                /* Combine the two 16 bit random numbers into one 32 bit */
        *pSeed=(((long)mother1[1])<<16)+(long)mother2[1];

                /* Return a double value between 0 and 1 
        return ((double)*pSeed)/m32Double;  */
}

/*  save data associated with a point on a curve.  
	Enter with name of file, a curve and a valid point on that curve.
	Returns 0 on success, -1 on failure.
*/

int save_curve (name, curv, point)
char * name;
CURVE * curv;
POINT * point;
{
	FILE	*save;
	int	err1, err2;

	save = fopen(name, "w");
	if ( !save) return(-1);
	err1 = fwrite(curv, sizeof(CURVE), 1, save);
	err2 = fwrite(point, sizeof(POINT), 1, save);
	if (!(err1 && err2)) return(-1);
	fclose(save);
	return(0);
}

/* get data saved to disk.
	Enter with name of file.
	Returns with curve and point on that curve restored, 0 function value
	or null results and -1 function value.
*/

int get_curve (name, curv, point)
char	*name;
CURVE	*curv;
POINT	*point;
{
	FILE	*getcrv;
	int	err1, err2;

	getcrv = fopen (name, "r");
	if (!getcrv) return(-1);
	err1 = fread(curv, sizeof(CURVE), 1, getcrv);
	err2 = fread(point, sizeof(POINT), 1, getcrv);
	fclose(getcrv);
	if (!(err1 && err2)) return(-1);
	return(0);
}

/*  Random number initialization requires some arbitrary input.  Request
	32 bits from coin tossing.  Feed to Mother of all random number
	generators.  Supposedly this generator has field size ~2^250.  That's
	roughly the size of the universe measured in cubic angstroms, so
	this should be as close to "random" as deterministic can get.
*/

void init_rand()
{
	FILE	*rand;
	INDEX	i;
	unsigned long mask;
	char	z1,cr;

	if ((rand = fopen("random.seed", "r")) == NULL) {
	   printf("\n pull out a coin.\n");
	   printf(" chose one side as '0'\n");
	   printf("  and the other side as '1'\n");
	   printf("   flip me some bits please\n");
	   random_seed = 0;
	   mask = 1;
	   i = 0;
	   while (i<32) {
	      printf("bit %d: ",i);
	      scanf("%c%c", &z1, &cr);
	      if (z1 == '1') {
		random_seed |= mask;
		i++;
		mask <<= 1;
	      } else if (z1 == '0') {
		i++;
		mask <<= 1;
	      }
	   }
	   return;
	}
	fread (&random_seed, sizeof(long), 1, rand);
	fclose(rand);
}

void close_rand()
{
	FILE	*rand;

	if ((rand = fopen("random.seed", "w")) != NULL) {
	   fwrite(&random_seed, sizeof(long), 1, rand);
	   fclose(rand);
	   return;
	}
	printf("\n Catastrophic Failure: random.seed not saved\n");
}

/*  print out a BIGINT with a label, to standard out.  */

void big_print (strng, a)
char * strng;
BIGINT * a;
{
	int i;

	printf("%s",strng);
	SUMLOOP(i) printf("%lx ",a->b[i]);
	printf("\n");
}

/*  Starting to get lazy, This needs to be part of a "point object" ultimately */

void print_point(title, p3)
char * title;
POINT * p3;
{
        printf("\n%s\n",title);
        big_print("x : ",&p3->x);
        big_print("y : ",&p3->y);
}

/*  generate a random point on a random curve.  Since these values are public anyway
	no need to attempt security measures on random seed or resulting points  */

void rand_curv_pnt( point, curve)
POINT * point;
CURVE * curve;
{
	BIGINT	f, y[2];
	INDEX	j;

/*  generate a random regular curve  */

	curve->form = 0;
	SUMLOOP(j) {
	   Mother(&random_seed);
	   curve->a6.b[j] = random_seed;
	}
	curve->a6.b[STRTPOS] &= UPRMASK;

/*  generate a random point on that curve */

	SUMLOOP(j) {
	   Mother(&random_seed);
	   point->x.b[j] = random_seed;
	}
	point->x.b[STRTPOS] &= UPRMASK;
	fofx (&point->x, curve, &f);
	while (gf_quadradic(&point->x, &f, &y[0]) > 0) {
	   point->x.b[LONGPOS] += 1L;
	   fofx(&point->x, curve, &f);
	}
	copy (&y[0], &point->y);
}

/*  This hash function is for educational purposes.  elliptic curves 
	have the property that there are some x's for which y^2 + x*y = f(x)
	has no solution for y.  Further, it takes 30 seconds to perform an
	elliptic multiply for one block of data.  A meg would be slow to hash.
*/

#define	WORDS_NEEDED	(LONGPOS-STRTPOS)

void eliptic_hash(num_words, data_ptr, result)
INDEX	num_words;
ELEMENT *data_ptr;
BIGINT	*result;
{
	static int init=0;
	static CURVE hcurv;
	static POINT hpnt;
	BIGINT	nxt_blok;
	INDEX	j, wrd_cnt;
	POINT	hashed, dashed;

/*  initialize hash curve and point only once  */

	if (!init) {
	   if (get_curve( "hash.curve", &hcurv, &hpnt) < 0) {
	      rand_curv_pnt(&hpnt, &hcurv);
	      if (save_curve( "hash.curve", &hcurv, &hpnt)) {
		printf("Error, can't create hash.curve\n");
	        exit(0);
	      }
	   }
	   init = -1;
	}

/*  initialize hash output value  */

	SUMLOOP(j) {
	   hashed.x.b[j] = hpnt.x.b[j];
	   hashed.y.b[j] = hpnt.y.b[j];
	}

/*  grab a block of data that completely fills long words.  Zero fill for
	last unused block < max length.
*/
	wrd_cnt = num_words;
	null(&nxt_blok);
	while (wrd_cnt) {
	   if (wrd_cnt >= WORDS_NEEDED) {
	      for (j=0; j < WORDS_NEEDED; j++)
		nxt_blok.b[STRTPOS + j] = *data_ptr++;
	      wrd_cnt -= WORDS_NEEDED;
	   } else {
	      null(&nxt_blok);
	      while (wrd_cnt) nxt_blok.b[STRTPOS + wrd_cnt--] = *data_ptr++;
	   }

/*  use block of data as multiplier to find next point on curve.  */

	   printf(".");
	   elptic_mul(&nxt_blok, &hashed, &dashed, &hcurv);
	   copy_point(&dashed, &hashed);
	}
	copy (&hashed.x, result);
	printf("\n");
}

/*  smash bits around to create a key.  experimental and for fun ok?!
	Take last 4 bits of each pair of input characters to create one byte
	of data block.  Hash data block using LONGPOS-STRTPOS ELEMENTS as
	multipliers of a single point, until whole data block consumed.  More
	than one or 2 factors is probably stupid (unless they are relatively
	prime).  And it would take too long.  The 256 character input restriction
	is much larger than most people use anyway.
*/

void elptic_key_gen(string, key)
char * string;
BIGINT * key;
{
	char	bit_string[128], *bs_ptr;
	char	byte0, byte1;
	int	byt_cnt;
	INDEX	num_elements;
	INDEX	i;

	byt_cnt = 0;
	bs_ptr = bit_string;
	for (i=0; i<128; i++) bit_string[i] = 0;
	while (*string) {
	   byte0 = (*string & 0xf) << 4;
	   string++;
	   byte1 = *string & 0xf;
	  *bs_ptr++ = byte0 | byte1;
	   byt_cnt++;
	   if (! *string) break;
	   else string++;
	}
	num_elements = byt_cnt/(WORDSIZE/8);
	if (! num_elements) {
	   printf("key size too small\n");
	   return;
	}
	eliptic_hash( num_elements, (ELEMENT *)bit_string, key);
}

/*  gnu complains about gets, build my own. replace with something better, please! */

int get_string(buf, max)
char * buf;
int  max;
{
	int limit;
	char *pointer;
	char ch;

	pointer = buf;
	limit = 0;
#ifdef MACHTEN
	fpurge(stdin);
#endif
	while ((limit < (max-1)) && ((ch = getchar()) != '\n')) {
	  *pointer = ch;
	  pointer++;
	  limit++;
	}
	*pointer = '\0';		/* null-terminate the string */
	return(limit);
}

/*  generate a public key.  If full = 0, only generates secret key.  
	for full = 1, fills entire public key with new random value.
*/

void public_key_gen( skey, pkey, full)
BIGINT	* skey;
PUBKEY	* pkey;
INDEX	full;
{
	char	pass[MAX_PHRASE_SIZE];

/*  NOTE:  this is not done correctly.  turning off echo is platform dependent.
	see routines in PGP (getstring(char *strbuf, unsigned maxlen, int echo) in
	random.c) for much better ways to do this.
*/

	printf("Enter pass phrase:\n");
	get_string(pass, MAX_PHRASE_SIZE);
	printf("\nGenerating secret key.\n");

	elptic_key_gen( pass, skey);
	if (!full) return;

/*  create random point and curve.  for large enough fields this is not too
	dangerous, but cardinality of curve and order of point really ought to
	be checked.
*/

	printf("\nGenerating public key.\n");
	rand_curv_pnt(&pkey->p, &pkey->crv);
	elptic_mul(skey, &pkey->p, &pkey->q, &pkey->crv);
	printf("\nOK, now what name and address for this key?\n");
	printf("Name: ");
	get_string(pkey->name, MAX_NAME_SIZE);
	printf("Address: ");
	get_string(pkey->address, MAX_NAME_SIZE);
}

/*  Save a public key to dsik file in ascii format.  File name taken from field
	of public key, up to first blank or tab.  .PUB added as extension.

	Returns 0 if ok, -1 on failure.
*/

static const char extensn[] = ".PUB";

int save_pub_key (pub)
PUBKEY * pub;
{
	FILE	*save;
	char	*cpy,*src;
	BIGINT	px, qx, ax, qbit, qxinv;
	char	filename[MAX_NAME_SIZE+5];
	INDEX	i,j;

/*  create key name file */

	src = pub->name;
	while (*src == ' ' || *src == '\t') src++;
	cpy = filename;
	while (*src != ' ' && *src != '\t') *cpy++ = *src++;
	*cpy = '\0';
	strcat (filename, extensn);
	if ((save = fopen(filename, "w")) == NULL) {
	   printf("can't create %s\n",filename);
	   return(-1);
	}

/*  use last bit of y to define all of it.  Store in msb of first ELEMENT used.
	So far as I can tell, this is valid for type 1 normal basis (i.e.
	there are no 2^m+1 for m congruent to 5 valid field primes.)
	Point p is always y[0], so no need to encode it.  For q, compute y/x
	to determine which y to use from quadradic solution.  See Menezes, pg 92.
*/

	copy(&pub->p.x, &px);
	copy(&pub->q.x, &qx);
	copy(&pub->crv.a6, &ax);
	opt_inv(&pub->q.x, &qxinv);
	opt_mul(&pub->q.y, &qxinv, &qbit);
	if (1 & qbit.b[LONGPOS]) qx.b[STRTPOS] |= SUBMASK;

/*  may want to add the following some time if a2 ever used, can be attached after
	a6 and full curve takes minimal storage:
	if (pub->crv.form) ax.b[STRTPOS] |= SUBMASK;
*/

	fprintf(save, "%s\n", pub->name);
	fprintf(save, "%s\n", pub->address);
	SUMLOOP(i) fprintf(save, "%lx ", px.b[i]);
	fprintf(save, "\n");
	SUMLOOP(i) fprintf(save, "%lx ", qx.b[i]);
	fprintf(save, "\n");
	SUMLOOP(i) fprintf(save, "%lx ", ax.b[i]);
	fprintf(save, "\n");
/*  output a2 here  */
	fclose(save);
	return(0);
}

/*  Recover a public key from disk file.  Assume ascii format of save_pub_key.
	Enter with file name (with or without extension) and pointer to a
	storage block.  Returns 0 on success, -1 on failure.
*/

int restore_pub_key(name, pub)
char * name;
PUBKEY * pub;
{
	FILE	*restore;
	char	filename[MAX_NAME_SIZE+5];
	INDEX	i,j;
	BIGINT	px, qx, ax, y[2], f;

/*  check for extension on file name and open file  */

	if ( !( j = (INDEX)strlen(name))) {
	   printf("filename too long: %s\n",name);
	   return(-1);
	}
	strcpy(filename,name);
	if (strcmp(&name[j-4], extensn) && j<=MAX_NAME_SIZE) 
	   strcat(filename,extensn);
	if ((restore = fopen(filename, "r")) == NULL) {
	   printf("can't open file %s\n");
	   return(-1);
	}

/*  read in raw data  */

	null( &px);
	null( &qx);
	null( &ax);
	fgets(pub->name, (size_t) MAX_NAME_SIZE, restore);
	pub->name[strlen( pub->name) - 1] = '\0';
	fgets(pub->address, (size_t)MAX_NAME_SIZE, restore);
	pub->address[strlen( pub->address) - 1] = '\0';
	SUMLOOP(i) fscanf(restore, "%lx", &px.b[i]);
	SUMLOOP(i) fscanf(restore, "%lx", &qx.b[i]);
	SUMLOOP(i) fscanf(restore, "%lx", &ax.b[i]);
/*  read in a2 here  */
	fclose(restore);

/*  create curve parameters.  fix this if form == 1 ever used.  */

	null(&pub->crv.a2);
	pub->crv.form = 0;
	copy(&ax, &pub->crv.a6);

	copy( &px, &pub->p.x);
	fofx( &px, &pub->crv, &f);
	if (gf_quadradic( &px, &f, &y[0])) {
	   printf("Key in file %s does not have valid point on given curve.\n",
			name);
	   printf("This is a major malfunction.\n");
	   return(-1);
	}
	copy (&y[0], &pub->p.y);

/*  get last bit of y/x for subscript into quadradic results  */

	if (qx.b[STRTPOS] & SUBMASK) {
	   j = 1;
	   qx.b[STRTPOS] &= UPRMASK;
	} else
	   j = 0;
	copy( &qx, &pub->q.x);
	fofx( &qx, &pub->crv, &f);
	if (gf_quadradic( &qx, &f, &y[0])) {
	   printf("Key in file %s does not have valid point on given curve.\n",
			name);
	   printf("This is a major malfunction.\n");
	   return(-1);
	}
	copy (&y[j], &pub->q.y);
	return(0);
}

void print_pubkey(pk)
PUBKEY * pk;
{

	printf("name: %s\n",pk->name);
	printf("address: %s\n",pk->address);
	printf("public key is:\n");
	big_print("curve: ",&pk->crv.a6);
	print_point("	P:",&pk->p);
	print_point("	Q:",&pk->q);
}
}

From msuinfo!agate!ihnp4.ucsd.edu!qualcomm.com!unix.ka9q.ampr.org!karn Wed Apr 20 17:29:26 1994
Path: msuinfo!agate!ihnp4.ucsd.edu!qualcomm.com!unix.ka9q.ampr.org!karn
From: karn@unix.ka9q.ampr.org (Phil Karn)
Newsgroups: sci.crypt
Subject: Re: Searching for primes and other things
Date: 18 Apr 1994 10:01:18 GMT
Organization: Qualcomm, Inc
Lines: 241
Distribution: inet
Message-ID: <2otlpe$66h@qualcomm.com>
References: <jhesseCo0LG3.JuD@netcom.com> <strnlghtCo17v8.BE3@netcom.com> <abellCo22E6.Gv1@netcom.com> <Co236B.G3H@news.Hawaii.Edu>
Reply-To: karn@servo.qualcomm.com
NNTP-Posting-Host: unix.ka9q.ampr.org

In article <Co236B.G3H@news.Hawaii.Edu>, wes@uhunix3.uhcc.Hawaii.Edu (Wes Peterson) writes:
|>      I found the recent discussion on finding prime numbers 
|> interesting and useful. 
|>      Now I have a couple of other questions. The protocol says, a) 
|> choose a large prime number p and then b) choose an element that is 
|> primitive mod p. I can do a). How do I do b)?


Here's a program I've been playing with lately that does this. It gets
around the problem you describe by generating a "strong" prime, i.e., 
(p-1)/2 is also prime. That way you know the prime factors of p-1:
2 and (p-1)/2.

The code requires the GNU multiple precision arithmetic library (libgmp).

--Phil


/* Generate a prime suitable for use as a Diffie-Hellman modulus,
 * i.e., (p-1)/2 is also prime. Also find a generator.
 * P. Karn, April 1994.
 */
#include <stdio.h>
#include <gnu/gmp.h>
#define	PLEN	1024	/* 1024 bits */
#define	SEARCHSPACE	5000000	/* Search range beyond starting point */

#define SIEVESIZE (SEARCHSPACE/2)	/* Sieve only includes odd numbers */

#define	BIT_SET(a,n)	((a)[(n)>>5] |= 1 << ((n) & 31))
#define BIT_CLEAR(a,n)	((a)[(n)>>5] &= ~(1 << ((n) & 31)))
#define	BIT_TEST(a,n)	((a)[(n)>>5] & (1 << ((n) & 31)))

unsigned long Smallsieve[SIEVESIZE/32];

long generator(MP_INT *p);

/* Construct sieve of prime numbers [3...SIEVESIZE*2] (odd numbers only) */
smallsieve(void)
{
	int j,k,p;

	memset(Smallsieve,0,sizeof Smallsieve);
	for(k=0;k < SIEVESIZE;k++){
		if(BIT_TEST(Smallsieve,k))
			continue;	/* 2*k+3 is composite */
		p = 2*k+3;	/* The next small prime */
		for(j=k+p;j<SIEVESIZE;j += p){
			BIT_SET(Smallsieve,j);	/* Mark all multiples of p */
		}
	}
}

main(argc,argv)
int argc;
char *argv[];
{
	MP_INT p,q,start,g,f,two,tmp;
	unsigned long sieve[SIEVESIZE/32];
	char *cp;

	int i,j,k;
	memset(sieve,0,sizeof(sieve));
	mpz_init(&p);
	mpz_init(&q);
	mpz_init(&start);
	mpz_init(&f);
	mpz_init(&tmp);
	mpz_init_set_ui(&two,2);

	printf("Generating small prime numbers...\n");
	smallsieve();

	/* Generate random starting point for subprime search,
	 * and ensure that it's odd
	 */
	if(argc < 2){
		printf("Generate random starting point\n");
		mpz_random(&p,PLEN/32);
	} else {
		printf("Using specified starting point\n");
		mpz_set_str(&p,argv[1],0);
		mpz_mod_2exp(&p,&p,PLEN);
	}
	/* starting q = (p-1)/2 */
	mpz_div_2exp(&start,&p,1);

	if((mpz_get_ui(&start) & 1) == 0)
		mpz_sub_ui(&start,&start,1);

	printf("Start q search at\n");
	cp = mpz_get_str(NULL,16,&start);
	fputs(cp,stdout);
	free(cp);
	printf("\n");

	/* p = 2*start + 1 */
	mpz_mul_2exp(&p,&start,1);
	mpz_add_ui(&p,&p,1);

	/* Sieve out q's and p's with small factors */
	printf("Sieving from starting point to q+%d...\n",SEARCHSPACE);

	for(i=0;i<SIEVESIZE;i++){
		int s,r;

		/* Get next small prime */
		if(BIT_TEST(Smallsieve,i))
			continue;
		s = 2*i+3;

		/* r = start mod s */
		r = mpz_mmod_ui(NULL,&start,s);

		k = s - r;	/* start+k is first entry divisible by s */
		if(k == s)
			k = 0;	/* s divides start */
		if(k & 1)	/* start+k even? */
			k += s;	/* Make start+k odd, and k even */
		/* The sieve omits the even numbers */
		k >>= 1;
		for(;k < SIEVESIZE;k += s){
			BIT_SET(sieve,k);	/* s divides start+2*k */
		}

		/* r = p mod s */
		r = mpz_mmod_ui(NULL,&p,s);

		k = s - r;	/* p+k is first entry divisible by s */
		if(k == s)
			k = 0;	/* s divides p */
		while(k & 3)
			k += s;

		/* The sieve omits the numbers divisible by 4 */
		k >>= 2;
		for(;k < SIEVESIZE;k += s){
			BIT_SET(sieve,k);	/* s divides p+2*k */
		}
	}
	printf("Sieve done, checking remaining candidates...\n");
	for(k=0;k<SIEVESIZE;k++){

		if(BIT_TEST(sieve,k))
			continue;	/* Definitely composite, skip */

		/* Candidate prime */			
		printf("test prime candidate at start+%d\n",2*k);
		mpz_add_ui(&q,&start,2*k);

		if(!mpz_probab_prime_p(&q,1))
			continue;
		printf("q passed Rabin-Miller test...\n");

		/* p = 2*q + 1 */
		mpz_mul_2exp(&p,&q,1);
		mpz_add_ui(&p,&p,1);

		if(!mpz_probab_prime_p(&p,1))
			continue;
		printf("p passed Rabin-Miller test...\n");
			break;
	}
	if(k == SIEVESIZE){
		printf("Failed to find a strong prime\n");
		exit(1);
	}
	printf("Found modulus p =\n");
	cp = mpz_get_str(NULL,16,&p);
	fputs(cp,stdout);
	free(cp);
	printf("\n");

	/* Find g, primitive root mod p */
	printf("Finding generator\n");
	i = generator(&p);
	printf("Generator g = %d decimal\n",i);
}

/* Find smallest primitive root (generator) for strong prime p using
 * algorithm on p. 209 of Schneier. Since we know (p-1)/2 is prime,
 * we know the factorization of p-1: it's simply 2 * (p-1)/2.
 * This makes our job *much* easier.
 */
long
generator(p)
MP_INT *p;
{
	MP_INT g,tmp,q;
	int i;

	mpz_init(&g);
	mpz_init(&tmp);
	mpz_init(&q);

	mpz_sub_ui(&q,p,1);
	mpz_div_2exp(&q,&q,1);	/* q = (p-1)/2 */

	/* Try 2. No need to test 2^2 mod p != 1 :-) */
	printf("Trying 2");
	mpz_set_ui(&g,2);
	mpz_powm(&tmp,&g,&q,p);	/* tmp = 2^q mod p */
	if(mpz_cmp_ui(&tmp,1) != 0){
		mpz_clear(&g);
		mpz_clear(&tmp);
		mpz_clear(&q);
		return 2;		/* 2 is primitive */
	}
	/* Try small primes starting with 3 */
	for(i=0;i<SIEVESIZE;i++){
		/* Get next small prime */
		if(BIT_TEST(Smallsieve,i))
			continue;
		printf(" %d",2*i+3);
		mpz_set_ui(&g,2*i+3);		/* g = trial generator */

		mpz_powm(&tmp,&g,&q,p);	/* tmp = g^q mod p */
		if(mpz_cmp_ui(&tmp,1) == 0)
			continue;		/* g is not primitive */

		/* This test can't possibly fail for small values of g,
		 * but it's here for completeness anyway
		 */
		mpz_powm_ui(&tmp,&g,2,p);	/* tmp = g^2 mod p */
		if(mpz_cmp_ui(&tmp,1) == 0)
			continue;		/* g is not primitive */

		break;				/* Passes both tests */
	}
	printf("\n");
	mpz_clear(&g);
	mpz_clear(&tmp);
	mpz_clear(&q);

	if(i == SIEVESIZE){
		printf("Could not find a small generator\n");
		return -1;
	}
	return(2*i+3);
}




/*
 * aestest - program to run AES test data files on specified algorithm
 *         Customise the ALG name and include file below and link with
 *         any alg satisfying the AES C-API.
 *
 * written by Lawrie Brown <lawre.Brown@adfa.oz.au> / May 1998
 */

#define ALG "LOKI97"		/*** Customise - algorithm name ***/
#include "loki97.h"		/*** Customise - algorithm header file ***/

char *usage = "aestest [-K|-E|-D [-e|-c] file] [-v]\n\
    \t\twith no options, runs all AES test files in current dir, OR\n\
    -K file\t\trun KAT test on named file\n\
    -E -e|-c file\trun encrypt MCT test in ECB|CBC mode on file\n\
    -D -e|-c file\trun decrypt MCT test in ECB|CBC mode on file\n\
    -v\t\t\tincrease verbosity";

#define MAXLINE	512		/* max line length in input test file */

/* define constants for the types of tests we recognise */
#define KAT	1
#define	EMCT	2
#define	DMCT	3

char *map_tests[] = {"None", "KAT", "Encrypt MCT", "Decrypt MCT"};

/* global variables */
char *fname = NULL;		/* name of custom test file */
int test_type = KAT;		/* type of test for custom file */
int test_mode = MODE_ECB;	/* mode of test for custom file */
int verbose = 0;		/* verbose output flag */

/* local func prototypes */
int chk_kat(int keysize, char *key, BYTE plain[], BYTE cipher[]);
int chk_e_ecb_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[]);
int chk_d_ecb_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[]);
int chk_e_cbc_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[]);
int chk_d_cbc_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[]);
int init(int argc, char **argv);
int runtest(char *filename, int test, int mode);
static BYTE *charToBYTE(BYTE *buf, char *hex, int len);
static int fromHex (char ch);
static int puthex(BYTE *out, int len, FILE *f);


/*
 * aestest main program - process all AES test files for specified algorithm
 */
int main(int argc, char **argv)
{

    init(argc, argv);				/* Process command-line args */

    if (fname) { 		/* run custom test file */
	runtest(fname,test_type,test_mode);
    } else {
	/* Run all standard AES test files assumed to be in current dir */
	runtest("ecb_vk.txt",KAT,MODE_ECB);
	runtest("ecb_vt.txt",KAT,MODE_ECB);
	runtest("ecb_tbl.txt",KAT,MODE_ECB);
	runtest("ecb_int.txt",KAT,MODE_ECB);
	runtest("ecb_e_m.txt",EMCT,MODE_ECB);
	runtest("ecb_d_m.txt",DMCT,MODE_ECB);
	runtest("cbc_e_m.txt",EMCT,MODE_CBC);
	runtest("cbc_d_m.txt",DMCT,MODE_CBC);
    }
}

/*
 * init - process command-line args, setting global flags as needed
 */
int init(int argc, char **argv)
{
    /* process options the old way so dont need getopt */
    while (argc > 1 && argv[1][0] == '-') {
        switch (argv[1][1]) {
            case 'K':		/* -K : KAT test */
                test_type = KAT;
                break;
            case 'E':		/* -E : Encrypt MCT test */
                test_type = EMCT;
                break;
            case 'D':		/* -D : Decrypt MCT test */
                test_type = DMCT;
                break;
            case 'e':		/* -e : in ECB mode */
                test_mode = MODE_ECB;
                break;
            case 'c':		/* -c : in CBC mode */
                test_mode = MODE_CBC;
                break;
            case 'v':		/* -v : increase verbosity */
                verbose++;
                break;
            default:
		fprintf(stderr, "Unknown arg %s\n", argv[1]);
            case 'h':
                fprintf(stderr,"%s\n",usage);
                exit(1);
        }
	argc--;
	argv++;
    }

    if (argc > 1)
	fname = argv[1];		/* custom test file given */
}

/*
 * runtest(filename,test,mode)
 *   - read and verify test data from filename,
 *     using the specified test (KAT, EMCT, DMCT) and mode (ECB or CBC)
 */
int runtest(char *filename, int test, int mode)
{
    FILE	*inp;			/* input file descriptor */
    char	s[MAXLINE];		/* buffer for next line read from inp */

				/* These hold the data for the next test */
    int		keysize = 0;		/* keysize in bits */
    int		i;			/* input number of this test */
    char	key[MAXLINE] = "";	/* key hex string */
    char	iv[MAXLINE] = "";	/* IV hex string */
    BYTE	pt[BLOCK_SIZE];		/* plaintext block */
    BYTE	ct[BLOCK_SIZE];		/* ciphertext block */

    int		total, good, bad;	/* counts of total, good & bad test */
    int		gotone = FALSE;		/* flag saying if reading a test */
    int		st;

    total = good = bad = 0;		/* zero counts */

    printf("### %s test %s for mode %s using file %s\n",
            ALG, map_tests[test], (mode==MODE_ECB?"ECB":"CBC"), filename);

    /* open test data file */
    inp = fopen(filename, "r");
    if (!inp) { printf("  failed: unable to open %s\n", filename); return 0; }

    /* read and process all lines from test data file */
    while ( fgets(s,sizeof(s),inp) ) {	/* read next line from test file */
	if (s[0] == '\n') {		/* blank line - treat as test delim */
	    if (gotone) {		/* have been collecting test data */
		if (test == KAT)
		    st = chk_kat(keysize, key, pt, ct);
		else if ((test == EMCT) && (mode == MODE_ECB))
		    st = chk_e_ecb_mct(keysize, key, iv, pt, ct);
		else if ((test == DMCT) && (mode == MODE_ECB))
		    st = chk_d_ecb_mct(keysize, key, iv, pt, ct);
		else if ((test == EMCT) && (mode == MODE_CBC))
		    st = chk_e_cbc_mct(keysize, key, iv, pt, ct);
		else if ((test == DMCT) && (mode == MODE_CBC))
		    st = chk_d_cbc_mct(keysize, key, iv, pt, ct);
		else st = 0;

		total++;
		if (st) good++;
		else	bad++;

	        gotone = FALSE;
	    }
	    if (verbose) fprintf(stderr,"  %s", s);
	} else if (strncmp("KEYSIZE=",s,8)==0) {	/* check wanted tags */
	    sscanf(s,"KEYSIZE=%d",&keysize);
	    if (verbose) fprintf(stderr,"KEYSIZE=%d\n", keysize);
	} else if (strncmp("I=",s,2)==0) {
	    sscanf(s,"I=%d",&i);
	    gotone = TRUE;			/* found another test case */
	    if (verbose) fprintf(stderr,"I=%d\n", i);
	} else if (strncmp("KEY=",s,4)==0) {
	    sscanf(s,"KEY=%s",key);
	    if (verbose) fprintf(stderr,"KEY=%s\n", key);
	} else if (strncmp("IV=",s,3)==0) {
	    sscanf(s,"IV=%s",iv);
	    if (verbose) fprintf(stderr,"IV=%s\n", iv);
	} else if (strncmp("PT=",s,3)==0) {
            charToBYTE(pt,s+3,sizeof(pt));
	    if (verbose) {fprintf(stderr,"PT="); puthex(pt,16,stderr); fprintf(stderr,"\n");}
	} else if (strncmp("CT=",s,3)==0) {
            charToBYTE(ct,s+3,sizeof(ct));
	    if (verbose) {fprintf(stderr,"CT="); puthex(ct,16,stderr); fprintf(stderr,"\n");}
	} else { 					/* otherwise ignore */
	    if (verbose) fprintf(stderr,"%s", s);
	}

    }

    /* display overall results */
    if (total == good)
        printf("  all %d tests OK\n", good);
    else
        printf("  ran %d tests with %d OK and %d FAILURES!\n", total, good, bad);
}


/* 
 *  chk_kat(keysize, key, pt, ct) - check KAT test for given key, plain, cipher
 */
int chk_kat(int keysize, char *key, BYTE plain[], BYTE cipher[])
{
    int			enok = TRUE, deok = TRUE;	/* success/fail flags */
    BYTE		etemp[BLOCK_SIZE], dtemp[BLOCK_SIZE];	/* tmp blocks */
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	aes_cipher;		/* AES cipherInstance */
    int	i, st;


    /* Init AES cipher in ECB mode */
    st = cipherInit(&aes_cipher, MODE_ECB, NULL);
    if (st != TRUE) { fprintf(stderr, "cipherInit failed with code %d\n", st); return FALSE; }

    /* Create key structs for encrypt */
    st = makeKey(&enc_key, DIR_ENCRYPT, keysize, key);
    if (st != TRUE) { fprintf(stderr, "makeKey failed with code %d\n", st); return FALSE; }

    /* test encrypt */
    st = blockEncrypt(&aes_cipher, &enc_key, plain, BLOCK_SIZE*8, etemp);
    if (st != TRUE) { fprintf(stderr, "blockEncrypt failed with code %d\n", st); return FALSE; }
    if (memcmp(etemp, cipher, sizeof(etemp)) != 0) enok = FALSE;
    if (verbose>1) {
        fprintf(stderr,"PT: "); puthex(plain,16,stderr);
        fprintf(stderr,"encrypt to: "); puthex(etemp,16,stderr);
    }
    if (verbose) fprintf(stderr,"  encrypt %s\t", (enok?"GOOD" : "FAILED"));

    /* Create key structs for encrypt */
    st = makeKey(&enc_key, DIR_DECRYPT, keysize, key);
    if (st != TRUE) { fprintf(stderr, "makeKey failed with code %d\n", st); return FALSE; }

    /* test decrypt */
    st = makeKey(&dec_key, DIR_DECRYPT, keysize, key);
    st = blockDecrypt(&aes_cipher, &dec_key, cipher, BLOCK_SIZE*8, dtemp);
    if (st != TRUE) { fprintf(stderr, "blockDecrypt failed with code %d\n", st); return FALSE; }
    if (memcmp(dtemp, plain, sizeof(dtemp)) != 0) deok = FALSE;
    if (verbose>1) {
        fprintf(stderr,"CT: "); puthex(cipher,16,stderr);
        fprintf(stderr,"decrypt to: "); puthex(dtemp,16,stderr);
    }
    if (verbose) fprintf(stderr,"  decrypt %s\n", (deok?"GOOD" : "FAILED"));

    return (enok && deok);	/* return TRUE only if both en & decrypt ok */
}


/* 
 *  chk_e_ecb_mct(keysize, key, iv, plain, cipher)
 *    check ECB Encrypt MCT given key, iv, plain and cipher
 */
int chk_e_ecb_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[])
{
    int 		enok = TRUE;		/* success/fail flag */
    BYTE		etemp[BLOCK_SIZE]; 	/* tmp blocks */
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	aes_cipher;		/* AES cipherInstance */
    int iters = 10000;				/* num iterations in MCT test */
    int	i, st;

    /* Init AES cipher in MODE_ECB */
    st = cipherInit(&aes_cipher, MODE_ECB, iv);
    if (st != TRUE) { fprintf(stderr, "cipherInit failed with code %d\n", st); return FALSE; }

    /* Create key structs for encrypt */
    st = makeKey(&enc_key, DIR_ENCRYPT, keysize, key);
    if (st != TRUE) { fprintf(stderr, "makeKey failed with code %d\n", st); return FALSE; }

    /* test encrypt */
    if (verbose>1) { fprintf(stderr,"PT: "); puthex(plain,16,stderr); }
    for (i=0; i<iters; i++) {
        st = blockEncrypt(&aes_cipher, &enc_key, plain, BLOCK_SIZE*8, etemp);
        if (st != TRUE) {
	    fprintf(stderr, "blockEncrypt failed with code %d\n", st);
	    break;
	}
	memcpy(plain, etemp, sizeof(etemp));	/* plain = etemp */
    }
    if (verbose>1) {
        fprintf(stderr,"encrypt in mct test to: "); puthex(etemp,16,stderr);
    }
    if (memcmp(etemp, cipher, sizeof(etemp)) != 0) enok = FALSE;

    if (verbose) fprintf(stderr,"  test %s\n", (enok?"GOOD" : "FAILED"));

    return enok;
}


/* 
 *  chk_d_ecb_mct(keysize, key, iv, plain, cipher)
 *    check ECB Decrypt MCT given key, iv, plain and cipher
 */
int chk_d_ecb_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[])
{
    int 		deok = TRUE;		/* success/fail flag */
    BYTE		dtemp[BLOCK_SIZE];	/* tmp block */
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	aes_cipher;		/* AES cipherInstance */
    int iters = 10000;				/* num iterations in MCT test */
    int	i, st;

    /* Init AES cipher in MODE_ECB */
    st = cipherInit(&aes_cipher, MODE_ECB, iv);
    if (st != TRUE) { fprintf(stderr, "cipherInit failed with code %d\n", st); return FALSE; }

    /* Create key structs for decrypt */
    st = makeKey(&dec_key, DIR_DECRYPT, keysize, key);
    if (st != TRUE) { fprintf(stderr, "makeKey failed with code %d\n", st); return FALSE; }

    /* test decrypt */
    if (verbose>1) { fprintf(stderr,"PT: "); puthex(plain,16,stderr); }
    for (i=0; i<iters; i++) {
        st = blockDecrypt(&aes_cipher, &dec_key, cipher, BLOCK_SIZE*8, dtemp);
        if (st != TRUE) {
	    fprintf(stderr, "blockDecrypt failed with code %d\n", st);
	    break;
	}
	memcpy(cipher, dtemp, sizeof(dtemp));	/* cipher = dtemp */
    }
    if (verbose>1) {
        fprintf(stderr,"decrypt in mct test to: "); puthex(dtemp,16,stderr);
    }
    if (memcmp(dtemp, plain, sizeof(dtemp)) != 0) deok = FALSE;

    if (verbose) fprintf(stderr,"  test %s\n", (deok?"GOOD" : "FAILED"));

    return deok;
}


/* 
 *  chk_e_cbc_mct(keysize, key, iv, plain, cipher)
 *    check CBC Encrypt MCT given key, iv, plain and cipher
 */
int chk_e_cbc_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[])
{
    int 		enok = TRUE;		/* success/fail flag */
    BYTE		prev[BLOCK_SIZE], etemp[BLOCK_SIZE]; /* tmp blocks */
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	aes_cipher;		/* AES cipherInstance */
    int iters = 10000;				/* num iterations in MCT test */
    int	i, st;

    charToBYTE(prev,iv,sizeof(prev));		/* init prev = iv */

    /* Init AES cipher in MODE_CBC */
    st = cipherInit(&aes_cipher, MODE_CBC, iv);
    if (st != TRUE) { fprintf(stderr, "cipherInit failed with code %d\n", st); return FALSE; }

    /* Create key structs for encrypt */
    st = makeKey(&enc_key, DIR_ENCRYPT, keysize, key);
    if (st != TRUE) { fprintf(stderr, "makeKey failed with code %d\n", st); return FALSE; }

    /* test encrypt */
    if (verbose>1) { fprintf(stderr,"PT: "); puthex(plain,16,stderr); }
    for (i=0; i<iters; i++) {
        st = blockEncrypt(&aes_cipher, &enc_key, plain, BLOCK_SIZE*8, etemp);
        if (st != TRUE) {
	    fprintf(stderr, "blockEncrypt failed with code %d\n", st);
	    break;
	}
	memcpy(plain, prev, sizeof(prev));	/* plain = prev */
	memcpy(prev, etemp, sizeof(prev));	/* prev = etemp */
    }
    if (verbose>1) {
        fprintf(stderr,"encrypt in mct test to: "); puthex(etemp,16,stderr);
    }
    if (memcmp(etemp, cipher, sizeof(etemp)) != 0) enok = FALSE;

    if (verbose) fprintf(stderr,"  test %s\n", (enok?"GOOD" : "FAILED"));

    return enok;
}


/* 
 *  chk_d_cbc_mct(keysize, key, iv, plain, cipher)
 *    check CBC Decrypt MCT given key, iv, plain and cipher
 */
int chk_d_cbc_mct(int keysize, char *key, char *iv, BYTE plain[], BYTE cipher[])
{
    int 		deok = TRUE;		/* success/fail flag */
    BYTE		dtemp[BLOCK_SIZE];	/* tmp blocks */
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	aes_cipher;		/* AES cipherInstance */
    int iters = 10000;				/* num iterations in MCT test */
    int	i, st;

    /* Init AES cipher in CBC MODE_CBC */
    st = cipherInit(&aes_cipher, MODE_CBC, iv);
    if (st != TRUE) { fprintf(stderr, "cipherInit failed with code %d\n", st); return FALSE; }

    /* Create key structs for decrypt */
    st = makeKey(&dec_key, DIR_DECRYPT, keysize, key);
    if (st != TRUE) { fprintf(stderr, "makeKey failed with code %d\n", st); return FALSE; }

    /* test decrypt */
    if (verbose>1) { fprintf(stderr,"PT: "); puthex(plain,16,stderr); }
    for (i=0; i<iters; i++) {
        st = blockDecrypt(&aes_cipher, &dec_key, cipher, BLOCK_SIZE*8, dtemp);
        if (st != TRUE) {
	    fprintf(stderr, "blockDecrypt failed with code %d\n", st);
	    break;
	}
	memcpy(cipher, dtemp, sizeof(dtemp));	/* cipher = dtemp */
    }
    if (verbose>1) {
        fprintf(stderr,"decrypt in mct test to: "); puthex(dtemp,16,stderr);
    }
    if (memcmp(dtemp, plain, sizeof(dtemp)) != 0) deok = FALSE;

    if (verbose) fprintf(stderr,"  test %s\n", (deok?"GOOD" : "FAILED"));

    return deok;
}


/* Returns a BYTE array from a string of hexadecimal digits. */
static BYTE *charToBYTE(BYTE *buf, char *hex, int len) {
    int i = 0, j = 0;
    while (j < len) {
        buf[j++] = (BYTE)((fromHex(hex[i++])<<4) | fromHex(hex[i++]));
    }
    return buf;
}


/* Returns number from 0 to 15 corresponding to hex digit ch */
static int fromHex (char ch) {
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


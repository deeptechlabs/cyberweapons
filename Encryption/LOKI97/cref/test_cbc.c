/*
 * test_cbc - simple program to run encrypt & decrypt LOKI97 CBC test triples
 *
 * written by Lawrie Brown / May 1998
 */

#include "loki97.h"

/* local func prototypes */
static BYTE *charToBYTE(BYTE *buf, char *hex, int len) ;
static int fromHex (char ch) ;
static int puthex(BYTE *out, int len, FILE *f);

int verbose = 0;	/* verbose flag for debugging */

main()
{
    /***********  VARIABLES  *********************************************/
    int enok = TRUE, deok = TRUE;
    char *hexkey      = "0000000000000000000000000000000000000000000000000000000000000000";
    char *hex_ecipher = "0FE9D4BB4225D98CE335644423256424"; /* MCT enc val */
    char *hex_dplain  = "8E9D5B5988135E0775976D4EF7A12CB7"; /* MCT dec val */
    char *hexIV       = "00000000000000000000000000000000";
    BYTE		plain[BLOCK_SIZE], cipher[BLOCK_SIZE];	/* pt, ct */
    BYTE		prev[BLOCK_SIZE], etemp[BLOCK_SIZE], dtemp[BLOCK_SIZE];
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	loki97_cipher;		/* AES cipherInstance */
    int iters = 10000;				/* num iterations in MCT test */
    int	i, st;

    /***********  MCT ENCRYPT TEST  **************************************/

    fprintf(stderr, "LOKI97 MCT Test\n");

    /* construct desired plain, temp and cipher blocks  for MCT encrypt test */
    memset(plain, 0, sizeof(plain));			/* plain = 0 */
    charToBYTE(prev, hexIV, sizeof(prev));		/* prev = iv */
    charToBYTE(cipher,hex_ecipher,sizeof(cipher));	/* cipher from hex */

    /* Init LOKI97 cipher in CBC mode */
    st = cipherInit(&loki97_cipher, MODE_CBC, hexIV);
    if (st != TRUE) fprintf(stderr, "cipherInit failed with code %d\n", st);

    /* Create key structs for encrypt */
    st = makeKey(&enc_key, DIR_ENCRYPT, 256, hexkey);
    if (st != TRUE) fprintf(stderr, "makeKey failed with code %d\n", st);

    /* test encrypt */
    fprintf(stderr,"Plaintext is: ");
    puthex(plain,16,stderr); fprintf(stderr,"\n");
    for (i=0; i<iters; i++) {
        st = blockEncrypt(&loki97_cipher, &enc_key, plain, sizeof(plain)*8, etemp);
        if (st != TRUE) {
	    fprintf(stderr, "blockEncrypt failed with code %d\n", st);
	    break;
	}
	if (verbose) {
	    fprintf(stderr,"  iter %d, pt: ", i); puthex(plain,16,stderr);
	    fprintf(stderr," ct: "); puthex(etemp,16,stderr);
	    fprintf(stderr,"\n");
	}
	memcpy(plain, prev, sizeof(plain));	/* plain = prev */
	memcpy(prev, etemp, sizeof(prev));	/* prev = etemp */
    }
    if (memcmp(etemp, cipher, sizeof(etemp)) != 0) enok = FALSE;
    fprintf(stderr,"Test encrypt: "); puthex(etemp,16,stderr);
    fprintf(stderr," %s\n", (enok?"GOOD" : "FAILED"));

    /**********  MCT DECRYPT TEST  ***************************************/
    /* construct desired plain, temp and cipher blocks  for MCT decrypt test */
    memset(cipher, 0, sizeof(cipher));
    charToBYTE(plain,hex_dplain,sizeof(plain));

    /* Re-init LOKI97 cipher in CBC mode */
    st = cipherInit(&loki97_cipher, MODE_CBC, hexIV);
    if (st != TRUE) fprintf(stderr, "cipherInit failed with code %d\n", st);

    /* Create key structs for decrypt */
    st = makeKey(&dec_key, DIR_DECRYPT, 256, hexkey);
    if (st != TRUE) fprintf(stderr, "makeKey failed with code %d\n", st);

    /* test decrypt */
    for (i=0; i<iters; i++) {
        st = blockDecrypt(&loki97_cipher, &dec_key, cipher, sizeof(cipher)*8, dtemp);
        if (st != TRUE) {
	    fprintf(stderr, "blockDecrypt failed with code %d\n", st);
	    break;
	}
	memcpy(cipher, dtemp, sizeof(cipher));	/* cipher = dtemp */
    }
    if (memcmp(dtemp, plain, sizeof(dtemp)) != 0) deok = FALSE;
    fprintf(stderr,"Test decrypt: "); puthex(dtemp,16,stderr);
    fprintf(stderr," %s\n", (deok?"GOOD" : "FAILED"));

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


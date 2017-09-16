/*
 * test_cbc - simple program to run encrypt & decrypt LOKI97 CFB1 test triples
 *
 * written by Lawrie Brown / May 1998
 */

#include "loki97.h"

/* local func prototypes */
static BYTE *charToBYTE(BYTE *buf, char *hex, int len) ;
static int fromHex (char ch) ;
static int puthex(BYTE *out, int len, FILE *f);


main()
{
    /***********  VARIABLES  *********************************************/
    int enok = TRUE, deok = TRUE;
    char *hexkey = "0000000000000000000000000000000000000000000000000000000000000000";
    char *hexIV  = "00000000000000000000000000000000";
    BYTE	plain[4] = {0xf0, 0x0f, 0xaa, 0x00};	/* plaintext*/
    BYTE	cipher[4] = {0xe0, 0x9e, 0xc8, 0x96};	/* ciphertext*/
    BYTE	etemp[BLOCK_SIZE], dtemp[BLOCK_SIZE];
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	loki97_cipher;		/* AES cipherInstance */
    int	i, st;

    fprintf(stderr, "LOKI97 CFB1 Test\n");

    /***********  CFB1 ENCRYPT TEST  **************************************/
    /* Init LOKI97 cipher in CFB1 mode */
    st = cipherInit(&loki97_cipher, MODE_CFB1, hexIV);
    if (st != TRUE) fprintf(stderr, "cipherInit failed with code %d\n", st);

    /* Create key structs for encrypt */
    st = makeKey(&enc_key, DIR_ENCRYPT, 256, hexkey);
    if (st != TRUE) fprintf(stderr, "makeKey failed with code %d\n", st);

    /* test encrypt */
    fprintf(stderr,"Plaintext is: ");
    puthex(plain,sizeof(plain),stderr); fprintf(stderr,"\n");
    st = blockEncrypt(&loki97_cipher, &enc_key, plain, sizeof(plain)*8, etemp);
    if (st != TRUE) fprintf(stderr, "blockEncrypt failed with code %d\n", st);
    if (memcmp(etemp, cipher, sizeof(cipher)) != 0) enok = FALSE;
    fprintf(stderr,"Test encrypt: "); puthex(etemp,sizeof(cipher),stderr);
    fprintf(stderr," %s\n", (enok?"GOOD" : "FAILED"));

    /**********  CFB1 DECRYPT TEST  ***************************************/
    /* Re-init LOKI97 cipher in CFB1 mode */
    st = cipherInit(&loki97_cipher, MODE_CFB1, hexIV);
    if (st != TRUE) fprintf(stderr, "cipherInit failed with code %d\n", st);

    /* Create key structs for decrypt */
    st = makeKey(&dec_key, DIR_DECRYPT, 256, hexkey);
    if (st != TRUE) fprintf(stderr, "makeKey failed with code %d\n", st);

    /* test decrypt */
    st = blockDecrypt(&loki97_cipher, &dec_key, etemp, sizeof(cipher)*8, dtemp);
    if (st != TRUE) fprintf(stderr, "blockDecrypt failed with code %d\n", st);
    if (memcmp(dtemp, plain, sizeof(plain)) != 0) deok = FALSE;
    fprintf(stderr,"Test decrypt: "); puthex(dtemp,sizeof(plain),stderr);
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


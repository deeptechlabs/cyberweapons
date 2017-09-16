#include <stdio.h>
#include "libcrypt.h"

main(argc, argv)
  int argc;
  char *argv[];
{
    DESState state;
    TripleDESState state3;
    unsigned char buf[8192], *cryptbuf, icv[8], tmp[8];
    BigInt big;
    FILE *infp, *outfp;
    int i, start, len, mode;
    unsigned char key[3][8], keybytes[16], *keys[3];

    if (argc < 6) {
	printf("Usage: testDES infile outfile [E/D] key mode (ECB, CBC, OFM, 3ECB, 3CBC, 3OFM).\n");
	exit(1);
    }

    keys[0] = key[0];
    keys[1] = key[1];
    keys[2] = key[2];

    infp = fopen(argv[1], "rb");
    outfp = fopen(argv[2], "wb");

    /* Seed PSEUDO RNG with passphrase and generate random key */

    seed_rng(argv[4], strlen(argv[4]));
    randomBytes(keybytes, 16, PSEUDO);

    if (strcmp(argv[5], "ECB") == 0)
	goto _ECB;
    else if (strcmp(argv[5], "CBC") == 0)
	goto _CBC;
    else if (strcmp(argv[5], "OFM") == 0)
	goto _OFM;
    else if (strcmp(argv[5], "3ECB") == 0)
	goto _3ECB;
    else if (strcmp(argv[5], "3CBC") == 0)
	goto _3CBC;
    else if (strcmp(argv[5], "3OFM") == 0)
	goto _3OFM;
    else {
	printf("Don't know %s mode.\n", argv[5]);
	fclose(infp);
	fclose(outfp);
	exit(1);
    }

    _ECB:
    key_crunch(keybytes, 16, key[0]);
    setupDESState(&state, key[0], (unsigned char *)NULL, ECB);

    len = 1;
    while ((len = fread(buf, 1, 8192, infp)) > 0) {
	if (strcmp(argv[3], "E") == 0)
	    bufferEncrypt(buf, len, &state);
	else
	    bufferDecrypt(buf, len, &state);
	fwrite(buf, 1, len, outfp);
    }
    fclose(infp);
    fclose(outfp);
    exit(0);

    _CBC:
    memcpy(key[0], argv[4], strlen(argv[4]));
    key_crunch(keybytes, 16, key[0]);
    memset(icv, 0, 8);
    setupDESState(&state, key[0], icv, CBC);

    len = 1;
    while ((len = fread(buf, 1, 8192, infp)) > 0) {
	if (strcmp(argv[3], "E") == 0)
	    bufferEncrypt(buf, len, &state);
	else
	    bufferDecrypt(buf, len, &state);
	fwrite(buf, 1, len, outfp);
    }
    exit(0);

    _OFM:
    key_crunch(keybytes, 16, key[0]);
    memset(icv, 0, 8);
    setupDESState(&state, key[0], icv, OFM);

    len = 1;
    while ((len = fread(buf, 1, 8192, infp)) > 0) {
	if (strcmp(argv[3], "E") == 0)
	    bufferEncrypt(buf, len, &state);
	else
	    bufferDecrypt(buf, len, &state);
	fwrite(buf, 1, len, outfp);
    }
    fclose(infp);
    fclose(outfp);


    /* Triple DES Stuff */

    _3ECB:
    key_crunch(keybytes, 16, key[0]);
    randomBytes(keybytes, 16, PSEUDO);
    key_crunch(keybytes, 16, key[1]);
    memcpy(key[2], key[0], 8);
    setupTripleDESState(&state3, keys, (unsigned char *)NULL, ECB3);

    len = 1;
    while ((len = fread(buf, 1, 8192, infp)) > 0) {
	if (strcmp(argv[3], "E") == 0) {
	    buffer3Encrypt(buf, len, &state3);
	}
	else {
	    buffer3Decrypt(buf, len, &state3);
	}
	fwrite(buf, 1, len, outfp);
    }
    fclose(infp);
    fclose(outfp);
    exit(0);

    _3CBC:
    key_crunch(keybytes, 16, key[0]);
    randomBytes(keybytes, 16, PSEUDO);
    key_crunch(keybytes, 16, key[1]);
    memcpy(key[2], key[0], 8);

    memset(icv, 0, 8);
    setupTripleDESState(&state3, keys, icv, CBC3);

    len = 1;
    while ((len = fread(buf, 1, 8192, infp)) > 0) {
	if (strcmp(argv[3], "E") == 0) {
	    buffer3Encrypt(buf, len, &state3);
	}
	else {
	    buffer3Decrypt(buf, len, &state3);
	}
	fwrite(buf, 1, len, outfp);
    }
    exit(0);

    _3OFM:
    key_crunch(keybytes, 16, key[0]);
    randomBytes(keybytes, 16, PSEUDO);
    key_crunch(keybytes, 16, key[1]);
    memcpy(key[2], key[0], 8);

    memset(icv, 0, 8);
    setupTripleDESState(&state3, keys, icv, OFM3);

    len = 1;
    while ((len = fread(buf, 1, 8192, infp)) > 0) {
	if (strcmp(argv[3], "E") == 0) {
	    buffer3Encrypt(buf, len, &state3);
	}
	else {
	    buffer3Decrypt(buf, len, &state3);
	}
	fwrite(buf, 1, len, outfp);
    }
    fclose(infp);
    fclose(outfp);

}


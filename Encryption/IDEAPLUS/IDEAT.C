/*****************************************************************************/
/*                        IDEA Encryption Algorithm                          */
/*****************************************************************************/
/*                                                                           */
/*   IDEA (International Data Encryption Algorithm) is a block encryption    */
/*   algorithm whose development results from a co-operation between the     */
/*   Swiss Federal Institute of Technology Zurich (ETHZ) and Ascom Tech Ltd. */
/*   IDEA encrypts or decrypts 64-bit data blocks, using symmetric 128-bit   */
/*   keys. The 128-bit keys are furthermore expanded to 52 16-bit subkeys.   */
/*                                                                           */
/*   For detailed technical information on IDEA contact:                     */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*   Patent rights of Ascom Systec Ltd. granted in Europe, Japan and the US. */
/*   All other rights reserved.                                              */
/*                                                                           */
/*   For detailed patent information on IDEA contact:                        */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*   Author:    Alain Beuchat/Daniel Zimmermann                              */
/*   Release:   2.0                                                          */
/*                                                                           */
/*****************************************************************************/
/*
 * File Name:		ideat.c
 *
 * Compile Option: 	TEST_SIZE: if defined examines the size of uint16,
 *				   uint32, int32, and prints a short report.
 *
 * Description:
 *	Test program for the IDEA block encryption algorithm.
 *	The initial {0, 1, 2, 3,} data block is encrypted and decrypted NENC
 *	times (3 tests using 3 different keys). After the last decryption,
 *	the last block should be the same as the initial data block.
 *	test_size() prints out warnings, suggestions, or comments regarding
 *	the type sizes chosen.
 */

#include <stdio.h>
#include "c_fct.h"
#include "ideaplus.h"

#define NENC 3		/* number of encryption */
#define TEST_SIZE	/* print a short report regarding the variable sizes */

#ifdef TEST_SIZE
_VOID_ test_size()
{
	int size_uint16 = sizeof(uint16);
	int size_uint32 = sizeof(uint32);
	int size_int32  = sizeof(int32);
	int size_short  = sizeof(short);
	int size_int    = sizeof(int);
	int size_long   = sizeof(long);
	int printed = 0;

	/* uint16 size test */
	if (size_uint16 < 2) {
		printf(" Warning: uint16 is too small, ");
		printf("at least two bytes are required:\n");
		printf("   --> typedef unsigned ");
		if (size_int == 2) printf("%s ","int");
		else if (size_long == 2) printf("%s ","long");
		printf("uint16;\n");
		printed = 1;
	}
	if ((size_uint16 > 2) && (size_short <= 2)) {
		printf(" Suggestion: uint16 is large, ");
		printf("only two bytes are required:\n");
		printf("   --> typedef unsigned ");
		if (size_short == 2) printf("%s ","short");
		else if (size_int == 2) printf("%s ","int");
		printf("uint16;\n");
		printed = 1;
	}
	if (!printed) printf(" Optimum size for uint16.\n");
	printed = 0;

	/* uint32 size test */
	if (size_uint32 < 4) {
		printf(" Warning: uint32 is too small, ");
		printf("at least four bytes are required:\n");
		printf("   --> typedef unsigned ");
		if (size_int == 4) printf("%s ","int");
		else if (size_long == 4) printf("%s ","long");
		printf("uint32;\n");
		printed = 1;
	}
	if ((size_uint32 > 4) && (size_short <= 4)) {
		printf(" Suggestion: uint32 is large, ");
		printf("only four bytes are required:\n");
		printf("   --> typedef unsigned ");
		if (size_short == 4) printf("%s ","short");
		else if (size_int == 4) printf("%s ","int");
		printf("uint32;\n");
		printed = 1;
	}
	if (!printed) printf(" Optimum size for uint32.\n");
	printed = 0;

	/* int32 size test */
	if (size_int32 < 4) {
		printf(" Warning: int32 is too small, ");
		printf("at least four bytes are required:\n");
		printf("   --> typedef ");
		if (size_int == 4) printf("%s ","int");
		else if (size_long == 4) printf("%s ","long");
		printf("int32;\n");
		printed = 1;
	}
	if ((size_int32 > 4) && (size_short <= 4)) {
		printf(" Suggestion: int32 is large, ");
		printf("only four bytes are required:\n");
		printf("   --> typedef unsigned ");
		if (size_short == 4) printf("%s ","short");
		else if (size_int == 4) printf("%s ","int");
		printf("int32;\n ");
		printed = 1;
	}
	if (!printed) printf(" Optimum size for int32.\n\n");
}
#endif /* TEST_SIZE */

main()
{
	int i, j, k;
	idea_key_t key[3];
	idea_subkeys_t enkey;
	idea_subkeys_t dekey;
	idea_block_t data;

	printf("\n");
	printf("**************************************************\n");
	printf("*           IDEA Algorithm Test Program          *\n");
	printf("**************************************************\n");
	printf("*                                                *\n");
	printf("* This program encrypts and decrypts%3d times    *\n",NENC);
	printf("* the initial block of data {0, 1, 2, 3}.        *\n");
	printf("* The last block must be the same as the initial *\n");
	printf("* block.                                         *\n");
	printf("*                                                *\n");
	printf("* Optionaly, some suggestions regarding the size *\n");
	printf("* of the data can be printed out.                *\n");
	printf("*                                                *\n");
	printf("**************************************************\n");
	printf("\n");

	/* Computation of the keys */
	for (i=0;i<8;i++) {
		key[0][i]= i+1; 
		if (i <= 3) key[1][i] = (i+1) * 1000; 
		else key[1][i] = (8-i) * 1000;
		if (i <= 4)
			key[2][i] = (i+1)*1000 + (i+1)*100 + (i+1)*10 + (i+1);
		else
			key[2][i] = (i-4)*1000 + (i-4)*100 + (i-4)*10 + (i-4);
	}

	/* Test with one key */
	for( k=0; k<3; k++) {
		idea_encrypt_subkeys(key[k],enkey);
		idea_decrypt_subkeys(enkey,dekey);

		printf("\n Key:         ");
		for (i=0;i<4;i++) printf(" %6d",enkey[i]);
		printf("\n              ");
		for (i=0;i<4;i++) printf(" %6d",enkey[4+i]);
		printf("\n Input block: ");
		for (i=0;i<4;i++) { 
			data[i]=i;
			printf(" %6d",data[i]);
		}
		for( j=0;j<NENC;j++) {
			idea_cipher(data,data,enkey);
			printf("\n encryption%3d",j+1);
			for (i=0;i<4;i++) printf(" %6d",data[i]);
		}
		for( j=NENC;j>0;j--) {
			idea_cipher(data,data,dekey);
			if (j == 1)
				printf("\n Last block:  ");
			else
				printf("\n decryption%3d",j-1);
			for (i=0;i<4;i++) printf(" %6d",data[i]);
		}
		printf("\n\n");
	}

#ifdef TEST_SIZE
	/* Check type sizes */
	test_size();
#endif /* TEST_SIZE */

	return(0);
}

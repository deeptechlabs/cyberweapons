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
 * File Name:		ideat.cpp
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

/* Reporting to IDEA.RPT instead of CON
 * ZES/Informatik FJK 07.03.94
 */
FILE * rpt;

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
		fprintf(rpt, " Warning: uint16 is too small, ");
		fprintf(rpt, "at least two bytes are required:\n");
		fprintf(rpt, "   --> typedef unsigned ");
		if (size_int == 2) fprintf(rpt, "%s ","int");
		else if (size_long == 2) fprintf(rpt, "%s ","long");
		fprintf(rpt, "uint16;\n");
		printed = 1;
	}
	if ((size_uint16 > 2) && (size_short <= 2)) {
		fprintf(rpt, " Suggestion: uint16 is large, ");
		fprintf(rpt, "only two bytes are required:\n");
		fprintf(rpt, "   --> typedef unsigned ");
		if (size_short == 2) fprintf(rpt, "%s ","short");
		else if (size_int == 2) fprintf(rpt, "%s ","int");
		fprintf(rpt, "uint16;\n");
		printed = 1;
	}
	if (!printed) fprintf(rpt, " Optimum size for uint16.\n");
	printed = 0;

	/* uint32 size test */
	if (size_uint32 < 4) {
		fprintf(rpt, " Warning: uint32 is too small, ");
		fprintf(rpt, "at least four bytes are required:\n");
		fprintf(rpt, "   --> typedef unsigned ");
		if (size_int == 4) fprintf(rpt, "%s ","int");
		else if (size_long == 4) fprintf(rpt, "%s ","long");
		fprintf(rpt, "uint32;\n");
		printed = 1;
	}
	if ((size_uint32 > 4) && (size_short <= 4)) {
		fprintf(rpt, " Suggestion: uint32 is large, ");
		fprintf(rpt, "only four bytes are required:\n");
		fprintf(rpt, "   --> typedef unsigned ");
		if (size_short == 4) fprintf(rpt, "%s ","short");
		else if (size_int == 4) fprintf(rpt, "%s ","int");
		fprintf(rpt, "uint32;\n");
		printed = 1;
	}
	if (!printed) fprintf(rpt, " Optimum size for uint32.\n");
	printed = 0;

	/* int32 size test */
	if (size_int32 < 4) {
		fprintf(rpt, " Warning: int32 is too small, ");
		fprintf(rpt, "at least four bytes are required:\n");
		fprintf(rpt, "   --> typedef ");
		if (size_int == 4) fprintf(rpt, "%s ","int");
		else if (size_long == 4) fprintf(rpt, "%s ","long");
		fprintf(rpt, "int32;\n");
		printed = 1;
	}
	if ((size_int32 > 4) && (size_short <= 4)) {
		fprintf(rpt, " Suggestion: int32 is large, ");
		fprintf(rpt, "only four bytes are required:\n");
		fprintf(rpt, "   --> typedef unsigned ");
		if (size_short == 4) fprintf(rpt, "%s ","short");
		else if (size_int == 4) fprintf(rpt, "%s ","int");
		fprintf(rpt, "int32;\n ");
		printed = 1;
	}
	if (!printed) fprintf(rpt, " Optimum size for int32.\n\n");
}
#endif /* TEST_SIZE */

main()
{
	int i, j, k;
	long iout;
	idea_key_t key[3];
	idea_subkeys_t enkey;
	idea_subkeys_t dekey;
	idea_block_t data;

	rpt = fopen("IDEA.RPT", "w+t"); /* FJK 7.3.94 */

	fprintf(rpt, "\n");
	fprintf(rpt, "**************************************************\n");
	fprintf(rpt, "*          IDEA Algorithm Test Program           *\n");
	fprintf(rpt, "**************************************************\n");
	fprintf(rpt, "*                                                *\n");
	fprintf(rpt, "* This program encrypts and decrypts%3d times    *\n",NENC);
	fprintf(rpt, "* the initial block of data {0, 1, 2, 3}.        *\n");
	fprintf(rpt, "* The last block must be the same as the initial *\n");
	fprintf(rpt, "* block.                                         *\n");
	fprintf(rpt, "*                                                *\n");
	fprintf(rpt, "* Optionaly, some suggestions regarding the size *\n");
	fprintf(rpt, "* of the data can be printed out.                *\n");
	fprintf(rpt, "*                                                *\n");
	fprintf(rpt, "**************************************************\n");
	fprintf(rpt, "\n");

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

		fprintf(rpt, "\n Key:         ");
		for (i=0;i<4;i++)
			fprintf(rpt, " %6d",enkey[i]);
		fprintf(rpt, "\n              ");
		for (i=0;i<4;i++)
			fprintf(rpt, " %6d",enkey[4+i]);
		fprintf(rpt, "\n Input block: ");
		for (i=0;i<4;i++) { /* 7.3.94 FJK */
			data[i]=i;
			fprintf(rpt, " %6d", data[i]);
		}
		for( j=0;j<NENC;j++) {
			idea_cipher(data,data,enkey);
			fprintf(rpt, "\n encryption%3d",j+1);
			for (i=0;i<4;i++) { /* 7.3.94 FJK */
				iout = data[i];
				fprintf(rpt, " %6ld", iout);
			}
		}
		for( j=NENC;j>0;j--) {
			idea_cipher(data,data,dekey);
			if (j == 1)
				fprintf(rpt, "\n Last block:  ");
			else
				fprintf(rpt, "\n decryption%3d",j-1);
			for (i=0;i<4;i++) { /* 7.3.94 FJK */
				iout = data[i];
				fprintf(rpt, " %6ld", iout);
			}
		}
		fprintf(rpt, "\n\n");
	}

#ifdef TEST_SIZE
	/* Check type sizes */
	test_size();
#endif /* TEST_SIZE */

	return(0);
}

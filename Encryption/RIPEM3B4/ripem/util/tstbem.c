/*--- tstasn1.c -- Program to test parsing of ASN1 strings.
 *
 *  Mark Riordan  7 May 1992.
 */

#include <stdio.h>
#include <fcntl.h>
#include "bemparse.h"

unsigned char  TestStr[] = {
	0x36,0x13,
   0x16,0x05,0x74,0x65,0x73,0x74,0x31,
   0x16,0x01,0x40,
   0x16,0x07,0x72,0x73,0x61,0x2e,0x63,0x6f,0x6d };

#define LINELEN 4000

unsigned char line[LINELEN];
int debug=0;

int
main(int argc, char *argv[])
{
	unsigned char *cptr = line;
	int ch, act;
	int inhand;
   FILE *instream=stdin;

	for(act=1; act<argc; act++) {
		if(strcmp(argv[act],"-d")==0) {
			debug = 1;
		} else if(argv[act][0] == '-') {
			fputs("Usage: tstbem [-d] infile\n",stderr);
			return 1;
		} else {
			instream = fopen(argv[act],"rb");
		}
	}

	printf("\n\n");
#ifdef MSDOS
	inhand = fileno(instream);
	setmode(inhand,O_BINARY|O_RDONLY);
#endif

	while(EOF != (ch = getc(instream))) {
		*(cptr++) = (unsigned char)ch;
	}
	BEMParse(line,stdout);

	return 0;
}


#include <stdlib.h>
#include <stdio.h>
#include "desx.h"
#include <ctype.h>

typedef union {
	unsigned long blok[2];
	unsigned int word[4];	/* short */
	unsigned char byte[8];
	} M68K;

extern void main(void);
extern void put8hex(unsigned char *), get8hex(unsigned char *);
extern int getone(void);
extern void unscrun(unsigned long *, unsigned char *);

void main() {
	char input[2];
	unsigned char work[8];
	M68K key, block, white, junk, *fill;
	int endeflg, val, i;
	struct DESXKey dxKey;
	struct DESXContext dxCon;

	fprintf(stdout, "Simple DESX encryptor.  In response\n");
	fprintf(stdout, "to the prompts, enter - \n\n");
	fprintf(stdout, "\tEn/De:  [edrsq] (encrypt decrypt random quit)\n");
	fprintf(stdout, "\tKey:    xx xx xx xx xx xx xx xx (8 pairs hex)\n");
	fprintf(stdout, "\tWhite:  xx xx xx xx xx xx xx xx (8 pairs hex)\n");
	fprintf(stdout, "\tInput:  xx xx xx xx xx xx xx xx (8 pairs hex)\n");

	for(;;) {
		fprintf(stdout, "\n\tEn/De:  ");
		val = scanf("%1s", input);
		
		if( val ) {
			tolower(input[0]);
			val = input[0];
			}
			
		switch( val ) {
		case 'e': endeflg = 0;
			break;
		case 'd': endeflg = 1;
			break;
		case 's' :
			fprintf(stdout, "\tKey:    ");
			put8hex(key.byte);
			fprintf(stdout, "\tWhite:  ");
			put8hex(white.byte);
			fprintf(stdout, "\tInput:  ");
			put8hex(block.byte);
			continue;
			break;
		case 'q' :
			fprintf(stdout, "\nSo long for now, folks!\n");
			fprintf(stdout, "<Press RETURN to exit>");
			exit(0);
			break;
		default:
			continue;
			break;
			}
		
		fprintf(stdout, "\tKey:    ");
		val = getone();
		switch( val ) {
		case 'o':
			key.blok[0] = block.blok[0];
			key.blok[1] = block.blok[1];
			break;
		default:
			ungetc(val, stdin);
			get8hex(key.byte);
			break;
			}
		fprintf(stdout, "\tWhite:  ");
		val = getone();
		switch( val ) {
		case 'o':
			white.blok[0] = block.blok[0];
			white.blok[1] = block.blok[1];
			break;
		case 'k':
			white.blok[0] = key.blok[0];
			white.blok[1] = key.blok[1];
			break;
		default:
			ungetc(val, stdin);
			get8hex(white.byte);
			break;
			}
		for( i = 0; i < 8; i++ ) {
			dxKey.DESKey64[i] = key.byte[i];
			dxKey.Whitening64[i] = white.byte[i];
			}

		DESXKeySetup(&dxCon, &dxKey);
		fprintf(stdout, "\tPostW:  ");
		unscrun(dxCon.PostWhitening64, work);
		put8hex(work);
		
		fprintf(stdout, "\tInput:  ");
		val = getone();
		switch( val ) {
		case 'k':
			block.blok[0] = key.blok[0];
			block.blok[1] = key.blok[1];
			break;
		default:
			ungetc(val, stdin);
			get8hex(block.byte);
			break;
			}
		if( endeflg == 0 )
			DESXEncryptBlock(&dxCon, block.byte, block.byte);
		else
			DESXDecryptBlock(&dxCon, block.byte, block.byte);

		fprintf(stdout, "\tOutput: ");
		put8hex(block.byte);
		}
		
	exit(0);
	}

void put8hex(block)
unsigned char *block;
{
	int val, out;
	for( val = 0; val < 4; val++ ) {
		out = *block++;
		fprintf(stdout, "%02x", out&0377);
		out = *block++;
		fprintf(stdout, "%02x ", out&0377);
		}
	putc('\n', stdout);
	return;
	}

void get8hex(into)
unsigned char *into;
{
	int val, in;
	for( val = 0; val < 8; val++ ) {
		if( scanf("%2x", &in) == 0 ) {
			getc(stdin);
			return;
			}
		into[val] = in&0377;
		}
	return;
	}
	
int getone() {
	int val;
	if( (val = getc(stdin)) != EOF )
		val = tolower(val);
	return(val);
	}

static void unscrun(outof, into)
unsigned long *outof;
unsigned char *into;
{
	*into++ = (unsigned char) ((*outof >> 24) & 0xffL);
	*into++ = (unsigned char) ((*outof >> 16) & 0xffL);
	*into++ = (unsigned char) ((*outof >>  8) & 0xffL);
	*into++ = (unsigned char) ( *outof++      & 0xffL);
	*into++ = (unsigned char) ((*outof >> 24) & 0xffL);
	*into++ = (unsigned char) ((*outof >> 16) & 0xffL);
	*into++ = (unsigned char) ((*outof >>  8) & 0xffL);
	*into   = (unsigned char) ( *outof        & 0xffL);
	return;
	}
	}

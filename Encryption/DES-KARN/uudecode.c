/* uudecode.c - convert ascii-encoded files back to their original form
 * Usage: uudecode [infile]
 *
 * This command differs from the regular UNIX one in that the embedded
 * file name "/dev/stdout" is recognized, allowing it to be used in a pipeline
 *
 * Written and placed in the public domain by Phil Karn, KA9Q 31 March 1987
 */
#include <stdio.h>
#define	LINELEN	80
main(argc,argv)
int argc;
char *argv[];
{
	char linebuf[LINELEN],*index(),*fgets();
	register char *cp;
	int linelen,i;
	FILE *in,*out;
	
	if(argc > 1){
		if((in = fopen(argv[1],"r")) == NULL){
			fprintf(stderr,"Can't read %s\n",argv[1]);
			exit(1);
		}
	} else
		in = stdin;

	/* Find begin line */
	while(fgets(linebuf,LINELEN,in) != NULL){
		if((cp = index(linebuf,'\n')) != NULL)
			*cp = '\0';
		if(strncmp(linebuf,"begin",5) == 0)
			break;
	}
	if(feof(in)){
		fprintf(stderr,"No begin found\n");
		exit(1);
	}
	/* Find beginning of file name */
	cp = &linebuf[6];
	if((cp = index(cp,' ')) != NULL)
		cp++;
	/* Set up output stream */
	if(cp == NULL || strcmp(cp,"/dev/stdout") == 0){
		out = stdout;
	} else if((out = fopen(cp,"w")) == NULL){
			fprintf(stderr,"Can't open %s\n",cp);
			exit(1);
	}
	/* Now crunch the input file */
	while(fgets(linebuf,LINELEN,in) != NULL){
		linelen = linebuf[0] - ' ';
		if(linelen == 0 || strncmp(linebuf,"end",3) == 0)
			break;
		for(cp = &linebuf[1];linelen > 0;cp += 4){
			for(i=0;i<4;i++)
				cp[i] -= ' ';
			putc((cp[0] << 2) | ((cp[1] >> 4) & 0x3),out);
			if(--linelen > 0)
				putc((cp[1] << 4) | ((cp[2] >> 2) & 0xf),out);
			if(--linelen > 0)
				putc((cp[2] << 6) | cp[3],out);
			linelen--;
		}
	}
	fclose(out);
}


/* DES "desk calculator"
 * Phil Karn
 * January 1987
 */
#include <stdio.h>
#include <ctype.h>
main()
{
	char key[8],work[8];
	char line[80];
	int keyset = 0;

	if(desinit(0) == -1){
		printf("DES initialization failed\n");
		exit(1);
	}
	printf("Enter in hexadecimal:\nk <key>\np <plaintext>\nc <ciphertext>\n");
	printf("s - standard DES mode\n");
	printf("f - fast mode (no IP)\n"); 
	for(;;){
		gets(line);
		if(feof(stdin))
			break;
		if(isupper(line[0]))
			line[0] = tolower(line[0]);
		switch(line[0]){
		case 's':
			desdone();
			desinit(0);
			if(keyset)
				setkey(key);
			break;
		case 'f':
			desdone();
			desinit(1);
			if(keyset)
				setkey(key);
			break;
		case 'k':	/* Set key */
			get8(&line[1],key);
			setkey(key);
			keyset = 1;
			break;
		case 'c':	/* Decrypt ciphertext */
			if(!keyset){
				printf("Enter key\n");
				break;
			}
			get8(&line[1],work);
			dedes(work);
			printf("Plaintext: ");
			put8(work);
			printf("\n");
			break;
		case 'p':	/* Encrypt plaintext */
			if(!keyset){
				printf("Enter key\n");
				break;
			}
			get8(&line[1],work);
			endes(work);
			printf("Ciphertext: ");
			put8(work);
			printf("\n");
			break;
		default:
			printf("eh?\n");
			break;
		}
	}
}
get8(buf,cp)
char *buf;
register char *cp;
{
	int ikey[8],i;

	sscanf(buf,"%2x%2x%2x%2x%2x%2x%2x%2x",&ikey[0],&ikey[1],&ikey[2],
		&ikey[3],&ikey[4],&ikey[5],&ikey[6],&ikey[7]);
	for(i=0;i<8;i++)
		*cp++ = ikey[i];
}
put8(cp)
register char *cp;
{
	int i;

	for(i=0;i<8;i++){
		printf("%02x ",*cp++ & 0xff);
	}
}

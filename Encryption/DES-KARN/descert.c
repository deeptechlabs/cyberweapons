#include <stdio.h>
main()
{
	char key[8],plain[8],cipher[8],answer[8];
	int i;
	int test;
	int fail;

	desinit(0);

	for(test=0;!feof(stdin);test++){

		get8(key);
		printf(" K: "); put8(key);
		setkey(key);

		get8(plain);
		printf(" P: "); put8(plain);

		get8(answer);
		printf(" C: "); put8(answer);

		for(i=0;i<8;i++)
			cipher[i] = plain[i];
		endes(cipher);

		for(i=0;i<8;i++)
			if(cipher[i] != answer[i])
				break;
		fail = 0;
		if(i != 8){
			printf(" Encrypt FAIL");
			fail++;
		}
		dedes(cipher);
		for(i=0;i<8;i++)
			if(cipher[i] != plain[i])
				break;
		if(i != 8){
			printf(" Decrypt FAIL");
			fail++;
		}
		if(fail == 0)
			printf(" OK");
		printf("\n");
	}
}
get8(cp)
char *cp;
{
	int i,t;

	for(i=0;i<8;i++){
		scanf("%2x",&t);
		if(feof(stdin))
			exit(0);
		*cp++ = t;
	}
}
put8(cp)
char *cp;
{
	int i;

	for(i=0;i<8;i++){
		printf("%02x",*cp++ & 0xff);
	}
}

#include <stdio.h>
int 
main(argc,argv)
int argc;
char *argv[]; 
{ 
	printf("Hello, world.\n"); 	
	/* sleep(5); */
	fprintf(stderr,"This is written in stderr.\n");
	printf("argc=%d   argv[1] = '%s'\n",argc,argv[1]);
	return 44; 
}

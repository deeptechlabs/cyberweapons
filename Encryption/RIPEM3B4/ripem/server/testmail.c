/*  testmail.c  --  Quick program to test "sendmail".
 *
 *  MRR  12 March 88
 */

#define BOOL int

#include <stdio.h>
#include "../main/list.h"
#include "../main/listprot.h"
#include "sendnetp.h"


char *Testmsg[] = {
  "To: mrr@scss3.cl.msu.edu",
  "Subject: Test of testmail.c",
  "",
  "Hi there",
  "Line 2",
  NULL
 };
	
main(argc,argv)
int argc;
char *argv[];
{
  char *line[10];
  char inp[100];
  int il = 0;
  char *eMailAddr, *cp;
  TypList msg_list;

	InitList(&msg_list);
	for(il=0; Testmsg[il]; il++) {
		cp = AddToList(NULL,Testmsg[il], strlen(Testmsg[il])+1,&msg_list);
		printf("Added: %s\n",Testmsg[il]);
		if(cp) fprintf(stderr,"%s\n",cp);
	}

  eMailAddr = "mrr@cl-next3";

  SendNetMail(eMailAddr,&msg_list);
	printf("This line is from testmail.c, stdout.  Type something.\n");
	gets(inp);
  fprintf(stderr,"This line is from testmail.c   - stderr - %s\n",inp);
}

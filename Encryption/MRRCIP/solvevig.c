/*-- solvevig.c -- Find possible solutions to a Vigenere cipher.
 *
 *  Mark Riordan  11 Jan 91
 */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include "p.h"

#define DEBUG 1


char alfa[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
char *cip;

#define ALFASIZE 26
#define CHARSETSIZE 256
char table[ALFASIZE][CHARSETSIZE];

#define MAXKEYS 20
#define MAXKEYSIZE 40

typedef struct struct_key {
	long int	   sk_close;
	char		   sk_key[MAXKEYSIZE];
	struct struct_key *sk_prev;
	struct struct_key *sk_next;
} typ_key;


long int ComputeCloseness P((int cipchars));
void ClearCount P((void));
void DumpKeyList P((typ_key *keyptr));


#define LARGEVAL   999999999L

typ_key *BegKeyList, *EndKeyList;

char *msg[] = {
"Program to help break Vigenere ciphers.",
"Usage:  solvevig -w wordlist [-c ciphertextfile] [-p] ",
" where",
"   wordlist is a list of words to try for the key,",
"	     one word per line, in lower case.",
"   ciphertextfile  is the file containing the ciphertext",
"	     (defaults to stdin).  Can be mixed case.",
"   -p	     means print the potential plaintext and other info",
"	     for each word in the wordlist (very long!).",
" The program tests for valid plaintext by testing potential",
" plaintext from each word in the wordlist against known statistical",
" properties of the English language.  When all potential keys",
" have been tested, the results of the top 20 best candidates",
" are listed",
NULL };

static char *author = "Mark Riordan  1100 Parker  Lansing MI  48912";

long int CharCount[CHARSETSIZE];

struct freqstruct {
  char	    f_ch;
  int	    f_freq;
} freqs[] = {
  'e',1231,
  't', 959,
  'a', 805,
  'o', 794,
  'n', 719,
  'i', 718,
  's', 659,
  'r', 603,
  'h', 514,
  'l', 403,
  'd', 365,
  'c', 320,
  'u', 310,
  'p', 229,
  'f', 228,
  'm', 225,
  'w', 203,
  'y', 188,
  'b', 162,
  'g', 161,
  'v',	93,
  'k',	52,
  'q',	20,
  'x',	20,
  'j',	10,
  'z',	 9,
  '\0',  0 };



main(argc,argv)
int argc;
char *argv[];
{
#define LINESIZE 80
#define MSGSIZE  20000

   char curkey[LINESIZE];
	int keyint[40];
   typ_key *keyptr, *lastkeyptr, *insertkeyptr;
	int nkey,jch, ordch, jkey, j;
   int cipchars=0;
	char *cptr, outch, ch;
   extern char *optarg;
   FILE *dictstream, *cipfilestream = stdin;
   char *dictfilename = 0, *cipfilename = 0;
   int argerror = 0, printplain = 0;
   long int closeness;

   while(EOF != (ch = getopt(argc,argv,"w:c:p"))) {
      switch(ch) {
	 case 'w':
	    dictfilename = optarg;
	    break;

	 case 'c':
	    cipfilename = optarg;
	    break;

	 case 'p':
	    printplain = 1;
	    break;

	 default:
	    argerror = 1;
      }
   }

   if(!dictfilename || argerror) {
      usage(NULL,msg);
      exit(1);
   }

   cptr = cip = (char *) malloc(MSGSIZE);
   if(!cip) {
      fputs("Unable to allocate memory.\n",stderr);
      exit(1);
   }

   if(cipfilename) {
      cipfilestream = fopen(cipfilename,"r");
      if(!cipfilestream) {
	 fprintf(stderr,"Unable to open %s\n",cipfilename);
	 exit(1);
      }
   }
   while(EOF != (jch = fgetc(cipfilestream))) {
      *(cptr++) = jch;
      cipchars++;
   }
   *cptr = '\0';

   cipchars = strlen(cip);

   keyptr = EndKeyList = (typ_key *) malloc(sizeof(typ_key));
   lastkeyptr = (typ_key *) 0;
   for(j=0; j<MAXKEYS; j++) {
      keyptr->sk_close = LARGEVAL;
      keyptr->sk_key[0] = '\0';
      keyptr->sk_next = lastkeyptr;
      lastkeyptr = keyptr;

      keyptr = (typ_key *) malloc(sizeof(typ_key));
      lastkeyptr->sk_prev = keyptr;
   }
   BegKeyList = lastkeyptr;
   BegKeyList->sk_prev = (typ_key *) 0;
   free(keyptr);


   dictstream = fopen(dictfilename,"r");
   if(!dictstream) {
      fprintf(stderr,"Unable to open %s\n",dictfilename);
      exit(1);
	}

	/* Build the Vigenere table.  For efficiency, have the ciphertext
	 * dimension of the table indexed directly by ASCII value, rather
	 * than by an ordinal 0-25 (i.e., A-Z).
	 */
	for(jkey=0; jkey<ALFASIZE; jkey++) {
		for(jch=0; jch<256; jch++) {
			table[jkey][jch] = 0;
		}
		  for(jch='A'; jch<='Z'; jch++) {
			  table[jkey][jch] = (jch+jkey > 'Z' ? jch+jkey-ALFASIZE : jch+jkey)
				+ ('a'-'A');
		  }
		for(jch='a'; jch<='z'; jch++) {
			table[jkey][jch] = jch+jkey > (int) 'z'
			  ? jch+jkey-ALFASIZE : jch+jkey;
		}
	}

	/* Loop through the words in the dictionary.  */
	while(fgets(curkey,LINESIZE,dictstream)) {

		nkey = strlen(curkey)-1;
      curkey[nkey] = '\0';

	   for(jkey=0; jkey<nkey; jkey++) {
		   keyint[jkey] = (ALFASIZE - (tolower(curkey[jkey])-'a')) % ALFASIZE;
	   }

      ClearCount();
	   for(jkey=0,cptr=cip; *cptr; cptr++,jkey=(jkey+1)%nkey) {
		   outch = table[keyint[jkey]][*cptr];
	 CharCount[outch]++;
		   if(printplain) putchar(outch);
      }
      closeness = ComputeCloseness(cipchars);
      if(printplain) printf("\n%10ld %s  p\n",closeness,curkey);
      if(closeness < EndKeyList->sk_close) {
	 keyptr = BegKeyList;
	 while(closeness > keyptr->sk_close) {
	    keyptr = keyptr->sk_next;
	 }
	 if(keyptr == EndKeyList) {
	    strcpy(EndKeyList->sk_key,curkey);
	    EndKeyList->sk_close = closeness;
	 } else {
	    /* Grab the last entry in the list and use it for
	     * this key.  Make the next-to-last entry in the list
	     * be EndKeyList.
	     */
	    insertkeyptr = EndKeyList;
	    EndKeyList->sk_prev->sk_next = (typ_key *) 0;
	    EndKeyList = EndKeyList->sk_prev;

	    strncpy(insertkeyptr->sk_key,curkey,MAXKEYSIZE);
	    insertkeyptr->sk_close = closeness;

	    /* Insert this new node before "keyptr" by making its
	     * previous be keyptr's previous and its next be keyptr.
	     */
	    insertkeyptr->sk_prev = keyptr->sk_prev;
	    insertkeyptr->sk_next = keyptr;

	    if(keyptr == BegKeyList) {
	       BegKeyList = insertkeyptr;
	    } else {
	       /* The node formerly just previous to keyptr, and whose
		* next field pointed to keyptr, now must point to us.
		*/
	       keyptr->sk_prev->sk_next = insertkeyptr;
	    }

	    /* We must change the node we just inserted before so
	     * that its previous pointer points to us.
	     */
	    keyptr->sk_prev = insertkeyptr;
	 }
      }
	}

   putchar('\n');
   keyptr = BegKeyList;
	DumpKeyList(keyptr);

	return 0;
}


long int
ComputeCloseness(cipchars)
int cipchars;
{
   int j, curch;
   long int OursPerTT, ExpectPerTT, diff, sumdiff;

   sumdiff = 0;

	for (j=0; curch=freqs[j].f_ch; j++) {
      OursPerTT = CharCount[curch] * 10000 / cipchars;
      ExpectPerTT = freqs[j].f_freq;
      diff = OursPerTT - ExpectPerTT;
      if(diff<0) diff = -diff;
      sumdiff += diff;
   }

   return(sumdiff);
}

void
ClearCount()
{
   int j;

   for (j=0; j<CHARSETSIZE; j++) {
      CharCount[j] = 0;
   }
}

void
DumpKeyList(keyptr)
typ_key *keyptr;
{
   while(keyptr) {
      printf("%10ld %s\n",keyptr->sk_close,keyptr->sk_key);
      keyptr = keyptr->sk_next;
   }
}
}

/***************************************************************************/
/* encode and decode radix64                                               */
/*                                                                         */
/*  Copyright (c) 1995 -- Carl M. Ellison                                  */
/*  This code is free for anyone to use, provided this copyright and       */
/*  statement are left attached.                                           */
/***************************************************************************/

char enctab[64] = {		/* radix64 encoding table */
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/' 
} ; /* enctab[] */

char dectab[256] = {		/* radix64 decoding table */
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 64, -1, -1,
   -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
   -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 
} ; /* dectab[] */

/***************************************************************************/
/* enc64 -- encode inbuff to outbuff, forcing \n every line_lth chars and  */
/*    indenting continuation lines.                                        */
/*    Caller needs to allocate more outbuff than needed by 4 or 5 bytes.   */
/***************************************************************************/

void enc64( outbuff, out_lth, polth, inbuff, inb_lth, line_lth, n_space )
char *outbuff ;			/* output buffer */
long out_lth ;			/* allocated length of the output buffer */
long *polth ;			/* actual length of output */
unsigned char *inbuff ;		/* input (binary) buffer */
long inb_lth ;			/* length of inbuff */
long line_lth ;			/* maximum line lth (-1 means infinite) */
long n_space ;			/* # spaces at start of each text line */
{
  long nl ;			/* # chars left in this line */
  char *b, *c ;			/* walking pointers */

  nl = line_lth ;
  b = inbuff ;
  c = outbuff ;

  while (  (inb_lth > 0)
	 &&(out_lth > 5) ) {
    /* encoding */
    c[0]=enctab[(b[0]>>2)&0x3f] ;
    c[1]=enctab[((b[0]&0x3)<<4)|((b[1]>>4)&0xf)] ;
    c[2]=enctab[((b[1]&0xf)<<2)|((b[2]>>6)&0x3)] ;
    c[3]=enctab[b[2]&0x3f] ;
    out_lth -= 4 ;		/* count the code bytes */
    switch (inb_lth) {		/* take care of the final bytes */
    case 1: c[2]='=' ;		/* only 1, so == */
    case 2: c[3]='=' ;		/* 2, so = */
      inb_lth = 0 ;		/* either way, we're done */
      c += 4 ;			/* but no spaces */
      *(c++) = '\n' ;		/* and there's an end of line */
      break ;

    default:
      inb_lth -= 3;
      b += 3 ;
      c += 4 ;
      nl -= 4 ;
      if (nl <= 0) {
	long i ;
	*(c++) = '\n' ;
	nl = line_lth ;
	for (i=0;i<n_space;i++)
	  *(c++) = ' ' ;
	out_lth -= 1 + n_space ;
      }
      break ;
    } /* switch */
  } /* while */
  *polth = c - outbuff ;
} /* enc64 */

/***************************************************************************/
/* dec64 -- decode radix64 from 0-terminated inbuff to outbuff.            */
/*   Caller needs to allocate 2 or 3 bytes more than needed in outbuff.    */
/***************************************************************************/

void dec64( outbuff, out_lth, polth, inbuff )
unsigned char *outbuff ;	/* output binary buffer */
long out_lth ;			/* allocated lth of outbuff */
long *polth ;			/* actual length of output */
char *inbuff ;			/* input text buffer */
{
  char d[4] ;			/* a buffer of 4 coded characters */
  char *cp = inbuff ;		/* walk inbuff */
  unsigned char *b = outbuff ;	/* walk outbuff */
  long di = 0 ;			/* index into d[] */
  char c ;			/* temp char */
  unsigned char *e = outbuff+out_lth-3 ; /* end pointer */

  while (  (b < e)		/* room to do output? */
	 &&((c = *(cp++))!= 0) ) { /* loop until end of string */
    if ((c = dectab[c]) >= 0) {	/* valid code character? */
      d[di++] = c ;		/* yes, valid char */
      if (di == 4) {		/* have a full set? */
	b[0]=(d[0]<<2)|((d[1]>>4)&0x3) ;
	b[1]=((d[1]&0xf)<<4)|((d[2]>>2)&0xf) ;
	b[2]=((d[2]&0x3)<<6)|d[3] ;
	b += 3 ;		/* have 3 new bytes */
	if (d[3]==64) b-- ;	/* if final '=', one less byte */
	if (d[2]==64) b-- ;	/* if 2nd '=', another less */
	di = 0 ;		/* start over */
      } /* done with the full set */
    } /* if dectab[c] >= 0 */
  } /* while not end of string */
  *polth = b - outbuff ;
} /* dec64 */


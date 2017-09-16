#include <stdio.h>

typedef unsigned char UC ;
typedef UC *UCP ;
typedef unsigned long UL ;
typedef UL *ULP ;

char enctab[64] ;
char dectab[256] ;

main()
{
  UL c ;
  char t = 0 ;

  for (c=0;c<256;c++) dectab[c] = -1 ;

  for (c='A';c<='Z';c++) {
    enctab[t]=c;
    dectab[c]=t++;
  }
  for (c='a';c<='z';c++) {
    enctab[t]=c;
    dectab[c]=t++;
  }
  for (c='0';c<='9';c++) {
    enctab[t]=c;
    dectab[c]=t++;
  }
  enctab[t]='+';
  dectab['+']=t++;
  enctab[t]='/';
  dectab['/']=t++;
  dectab['=']=64 ;			/* flag for the byte-deleting char */



  /* print the forward and reverse tables */
  printf( "char enctab[64] = {\n" ) ;
  for (t=0;t<64;t++)
    switch (t & 0xf) {
    case 0: printf( "  '%c',", enctab[t] ) ; break ;
    case 15: printf( "'%c'%c\n", enctab[t], (t==63)?' ':',' ) ; break ;
    default: printf( "'%c',", enctab[t] ) ; break ;
    }
  printf( "}\n" ) ;
  putchar('\n');
  putchar('\n');
  printf( "char dectab[256] = {\n" ) ;
  for (c=0;c<256;c++)
    switch (c & 0xf) {

    case 0: printf( "   %2d,", dectab[c] ) ; break ;
    case 15: printf( " %2d%c\n", dectab[c], (c==255)?' ':',' ) ; break ;
    default: printf( " %2d,", dectab[c] ) ;  break ;
    }
  printf( "}\n" ) ;
} /* main */

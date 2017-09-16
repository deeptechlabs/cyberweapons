#include <stdio.h>

main()
{
  char inbuff[BUFSIZ] ;
  char outbuff[BUFSIZ] ;
  long olth ;

  while (fgets( inbuff, BUFSIZ, stdin) != NULL) {
    dec64( outbuff, BUFSIZ, &olth, inbuff ) ;
    fwrite( outbuff, 1, olth, stdout ) ;
  }

}

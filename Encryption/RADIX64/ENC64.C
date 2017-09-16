#include <stdio.h>

#define LINES  (10 * 48)
#define CLINES (2 * LINES)

main()
{
  char inbuff[LINES] ;
  char outbuff[CLINES] ;
  long olth ;
  long ilth ;

  while ((ilth = fread( inbuff, 1, LINES, stdin )) > 0) {
    enc64( outbuff, CLINES, &olth, inbuff, ilth, 64, 0 ) ;
    fwrite( outbuff, 1, olth, stdout ) ;
  }

}

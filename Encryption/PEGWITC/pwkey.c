#include "conio.h"
#include "stdio.h"

int main( unsigned argc, char * argv[] ) 
{
  _cputs( "Enter secret key - CTRL-Z when done\n" );
  while (1)
  {
    int x = _getch();
    if ( x == 26 ) break;
    if ( x == 13 ) x = 10;
    fputc( x, stdout );
    _putch( 'x' );
    //printf("%d ",x);
  }
  return 0;
}


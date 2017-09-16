#include "conio.h"
#include "stdio.h"
#include "time.h"

int bits( long x )
{
  int result = 0;
  while (x)
  {
    x /= 2;
    result += 1;
  }
  return result;
}

int main( unsigned argc, char * argv[] ) 
{
  
  long counter,old_counter=0;
  int old_x=0;
  int x,estimate=0;

  fprintf( stderr, "Pwjunk v2.0 : please press random keys until estimate reachs at least 128\n"
                   "Type CTRL-Z to finish\n" );
  while (1)
  {
    fprintf( stderr, "\rEstimate=%3d", estimate );
    counter = 0;
    while (!kbhit())
      counter += 1;
      
    x = _getch();
    printf( "%ld:%d ", counter-old_counter, x-old_x );
    estimate += bits(counter-old_counter);
    if ( x == 26 )
    {
      if ( estimate > 128 ) break;
    }
    else
    {
      estimate += bits(x-old_x);          
    }
    old_counter = counter;
    old_x = x;   
  }
  fprintf( stderr, "\n" );
  return 0;
}


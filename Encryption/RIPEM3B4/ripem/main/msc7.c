/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- msc7.c -- Routines to translate between Microsoft C 5.x/6.0
 *  and MSC 7.0.
 *
 *  Mark Riordan 4 July 1992
 */

#include <stdio.h>
#include <stdlib.h>
#include <dos.h>
#include <conio.h>
#include <io.h>

#ifdef _MSC_VER
#if _MSC_VER >= 700
/*--- Functions to ease the transition from Microsoft C 5.x/6.0
 *   to MS C 7.0
 */

int inp(unsigned port)
{
  return _inp(port);
}

int outp(unsigned port, int databyte)
{
  return _outp(port,databyte);
}

int getch(void)
{
  return _getch();
}

int getche(void)
{
  return _getche();
}

#ifndef WINNT
#define REGS _REGS

int intdos(union REGS *inregs, union REGS *outregs)
{
  return _intdos(inregs,outregs);
}
#endif

void ftime(timeptr)
struct _timeb *timeptr;
{
  _ftime(timeptr);
}

int read(int handle, void *buffer, unsigned count)
{
  return _read(handle,buffer,count);
}

int write(int handle, void *buffer, unsigned count)
{
  return _write(handle,buffer,count);
}

int close(int handle)
{
  return _close(handle);
}

int fileno(FILE *stream)
{
  return _fileno(stream);
}

int setmode(int handle, int mode)
{
  return _setmode(handle,mode);
}

_onexit_t onexit(_onexit_t funct)
{
  return _onexit(funct);
}

#endif
#endif

/*
 * Read and write slashified characters.
 * Translated from Tim Shepard's CLU code. 
 */

#include	<stdio.h>

#define	EOL	(-37)

write_char(out, c)
FILE	*out;
int		c;
{
   char	*s;
   char	buf[6];

   if (c == '\\')
      {s = "\\\\";}
   else if (c == '\n')
      {s = "\\n";}
   else if (c == '\t')
      {s = "\\t";}
   else if (c == '\f')
      {s = "\\p";}
   else if (c == '\b')
      {s = "\\b";}
   else if (c == '\r')
      {s = "\\r";}
   else if (c < ' ' || '~' < c)  {
      s = buf;
	  s[0] = '\\';
	  s[1] = '0' + (c/64);
	  s[2] = '0' + ((c%64)/8);
	  s[3] = '0' + (c%8);
	  s[4] = '\000';
	  }
   else  {
      s = buf;
	  s[0] = c;
	  s[1] = '\000';
      }

   fprintf(out, "%s", s);
}


int	read_char(inp)
FILE	*inp;
{
   int	c;

   c = getc(inp);
   if (c == EOF) return(EOF);
   if (c == '\n') return(EOL);
   if (c == '\\')  {
      c = getc(inp);
	  if (c == EOF) return(EOF);
      if (c == 'n')
	     {c = '\n';}
      else if (c == 't')
	     {c = '\t';}
      else if (c == 'p')
	     {c = '\f';}
      else if (c == 'b')
	     {c = '\b';}
      else if (c == 'r')
	     {c = '\r';}
      else if ('0' <= c  &&  c <= '7')  {
	     c = 64*(c - '0');
		 c = c + 8*(getc(inp)-'0');
		 c = c + 1*(getc(inp)-'0');
		 }
   }
   return(c);
}

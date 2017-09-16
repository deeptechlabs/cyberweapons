/*--- function usage -----------------------------------------------
 *
 *  Prints out a "usage" message.
 *
 *  Entry    msg points to an array of pointers to zero-terminated
 *		 strings.
 */
#include <stdio.h>

void
usage(line1,msg)
char *line1;
char **msg;
{
   if(line1) {
      fputs(line1,stderr);
      fputc('\n',stderr);
   }
   while(*msg) {
      fputs(*msg,stderr);
      fputc('\n',stderr);
      msg++;
   }
}
}

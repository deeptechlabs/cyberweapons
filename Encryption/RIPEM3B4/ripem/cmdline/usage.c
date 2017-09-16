/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- function usage -----------------------------------------------
 *
 *  Prints out a "usage" message.
 *
 *  Written by Mark Riordan in late 1990.
 *  This code is hereby placed in the public domain.
 *
 *  Entry  errorMessage  points to a zero-terminated string that will
 *                 be written to the standard error stream.
 *                 This would typically be a one-line error message.
 *          msg    points to an array of pointers to zero-terminated
 *                 strings to be written to standard output.
 *                 This would typically be a general-purpose "usage"
 *                 message.
 */
#include <stdio.h>
#include "usagepro.h"

void usage (errorMessage, msg)
char *errorMessage;
char **msg;
{
  while (*msg) {
    fputs (*msg, stdout);
    fputc ('\n', stdout);
    msg++;
  }

  if (errorMessage) {
    fputs (errorMessage, stderr);
    fputc ('\n', stderr);
  }
  else
    fputs ("Usage message sent to standard output.\n", stderr);
  fflush(stderr);
}

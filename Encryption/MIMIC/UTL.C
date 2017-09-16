#define UTL_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

#include "global.h"

#include "utl.h"

#if defined(FLG_PROTOTYPE)
void Error(const char msg[])
#else
void Error(msg)
char msg[];
#endif
{
char response[255 + 1];

fprintf(stderr, "%s\n", msg);
if (OpenGrammarFile == stdin || OpenSourceFile == stdin) {
  fprintf(stderr, "Reading from a pipe; must abort\n");
  exit(1);
  }
fprintf(stderr, "Continue? (Type quit to say goodbye)\n");

/* This isn't very nice if mimic is being used as a pipe.  A
   more Unix-like solution would be to read the response from /dev/tty...
*/
fgets(response, sizeof(response), stdin);
if (strncmp(response, "quit", 4) == 0)
  exit(1);
}

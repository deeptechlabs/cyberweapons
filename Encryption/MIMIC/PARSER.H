#if !defined(PARSER_H)
#define PARSER_H TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/
#include "global.h"

/* This section will try and parse output that should have come from the
   table built in TableSetter. Of course if it doesn't correspond, there will
   be problems. */

/* Note to users: This parser is really just a toy. It doesn't do any of the
  cool things that a full-fledges implementation might do. Feel free to play
  with it and make it better.

  Right now its limitations are:

  1) Each production of the grammar must begin with a terminal.
  2) A fixed amount of look-ahead specified at compile time.
  3) A host of compromises that get in the way of making the files
     completely flexible as they could or should be.
*/

#if defined(FLG_PROTOTYPE)
void DoItAllLoop(void);
#else
void DoItAllLoop();
#endif

#endif /* PARSER_H */

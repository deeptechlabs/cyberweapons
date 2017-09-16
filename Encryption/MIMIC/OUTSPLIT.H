#if !defined(OUTSPLIT_H)
#define OUTSPLIT_H TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

/* This unit uses the structures built in TableSetter to produce output
   from the grammar. */

#if defined(FLG_PROTOTYPE)
void DoSomeMimicry(void);
#else
void DoSomeMimicry();
#endif
/* This produces some randomness and keeps it all going until the end... */

#endif /* OUTSPLIT_H */

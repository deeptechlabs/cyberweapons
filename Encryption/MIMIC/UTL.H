#if !defined(UTL_H)
#define UTL_H TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

#if defined(FLG_PROTOTYPE)
void Error(const char msg[]);
#else
void Error();
#endif

#endif /* UTL_H */

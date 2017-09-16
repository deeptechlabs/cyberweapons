/* hookspriv.h */
/* Functions that the rest of the world doesn't have to see...  */

#ifndef YARROW_HOOKS_PRIV_H
#define YARROW_HOOKS_PRIV_H

/* Fun with Macros */
#define MCHECK(ptr) if(ptr==NULL) {return HOOKS_ERR_NULL_POINTER;}

/* Helpers */
BOOL WriteMouseTime(int limit);
BOOL WriteMouseMove(int limit);
BOOL WriteKeyTime(int limit);
BOOL WriteData(int entropy_source,LPVOID data,int size);
void setupCounter(void);

#endif
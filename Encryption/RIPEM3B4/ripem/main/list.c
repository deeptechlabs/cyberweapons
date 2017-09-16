/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- list.c -- Routines to implement "lists" ------------------
 *
 *  Mark Riordan  25 May 1992.
 *  This code is placed in the public domain.
 */
#include <stdio.h>
#include <ctype.h>
#if !defined(__MACH__) && !defined(MACTC) && !defined(I386BSD) && \
    !defined(apollo)   && !defined(__TURBOC__)  && !defined(mips) /*EWS*/
#include <malloc.h>
#endif
#include <stdlib.h>
#include <string.h>

#define BOOL int

#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "strutilp.h"


/*--- function InitList ----------------------------------------
 *
 *  Initialize a list.
 */
void
InitList(list)
TypList *list;
{
  list->firstptr = list->lastptr = NULL;
}

/*--- function AddToList ------------------------------------
 *
 *  Add an entry to a list.
 *
 *   Entry: prevEntry is the list entry member after which we wish to add
 *                an entry.  If NULL, add to end of list.
 *          entry     points to a string of bytes we wish to add.
 *        entryLen  is the number of bytes in the entry.
 *
 *   Exit:   Returns NULL if successful, else pointer to error message.
 *        Allocates memory for the entry structure and inserts it into the
 *         list at the desired point.  Memory for the entry data itself
 *       is not allocated; the list points directly to "entry".
 */
char *
AddToList(prevEntry,entry,entryLen,list)
TypListEntry *prevEntry;
void *entry;
unsigned int entryLen;
TypList *list;
{
  TypListEntry *new_entry;
  
  new_entry = (TypListEntry *) malloc(sizeof *new_entry);
  
  if(!new_entry) return "Can't allocate memory.";
  
  if(prevEntry) {
    new_entry->nextptr = prevEntry->nextptr;
    new_entry->prevptr = prevEntry;
    if(prevEntry->nextptr) {
      prevEntry->nextptr->prevptr = new_entry;
    } else {
      /* There was no next entry, so this is the new last entry. */
      list->lastptr = new_entry;
    }
    prevEntry->nextptr = new_entry;
  } else {
    /* Add to end of list. */
    /* If there's anything on the list, back point this new entry to it. */
    if(list->lastptr) {
      new_entry->prevptr = list->lastptr;
      new_entry->prevptr->nextptr = new_entry;
    } else {
      /* Empty list.  No previous or next entries.
       * Set beginning of list to this entry.
       */
      new_entry->prevptr = NULL;
      list->firstptr = new_entry;
    }
    new_entry->nextptr = NULL;
    list->lastptr = new_entry;
  }
  
  new_entry->dataptr = entry;
  new_entry->datalen = entryLen;

  return NULL;
}

/*--- function AppendLineToList ----------------------------------------------
 *
 *  Add a zero-terminated line to the end of a list.
 *
 *  Entry:  line    is a zero-terminated line.
 *        list    points to a list.
 *
 *   Exit:  We have allocated memory for a copy of the line, and added
 *         this copy to the end of the list.
 */
char *
AppendLineToList(line,list)
char *line;
TypList *list;
{
  char *lptr;
  
  if(!strcpyalloc(&lptr,line)) return "Can't allocate memory."; 
  return AddToList(NULL,lptr,strlen(lptr)+1,list);
}

/*--- function FreeList ---------------------------------------------------
 *
 *  Zeroize and free all the entries in a list.  Also re-initialize the list.
 *
 *  Entry:  list    points to a TypList data structure.
 *
 *   Exit:  All the entries in the data structure have been freed.
 */
void
FreeList(list)
TypList *list;
{
  TypListEntry *entry, *next_entry;
  
  for(entry=list->firstptr; entry; ) {
    next_entry = entry->nextptr;
    
    /* Zeroize and free the data pointed to by this entry. */
    R_memset ((POINTER)entry->dataptr, 0, entry->datalen);
    free(entry->dataptr);
    
    /* Free the entry structure itself. */
    free(entry);
    entry = next_entry;
  }

  InitList (list);
}

/* Like AddToList, except inserts at the beginning.
 */
char *PrependToList (entry, entryLen, list)
void *entry;
unsigned int entryLen;
TypList *list;
{
  TypListEntry *new_entry;
  
  new_entry = (TypListEntry *)malloc(sizeof (*new_entry));
  
  if (!new_entry)
    return "Can't allocate memory.";
  
  /* If there's anything on the list, point first entry to the new entry. */
  if (list->firstptr) {
    new_entry->nextptr = list->firstptr;
    new_entry->nextptr->prevptr = new_entry;
  } else {
    /* Empty list.  No previous or next entries.
       Set beginning of list to this entry.
     */
    new_entry->nextptr = NULL;
    list->lastptr = new_entry;
  }
  new_entry->prevptr = NULL;
  list->firstptr = new_entry;
  
  new_entry->dataptr = entry;
  new_entry->datalen = entryLen;

  return NULL;
}


/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* ripemsoc.c */
char *GetUserRecordFromServer
  P((char *, TypKeySource *, char *, int, BOOL *, BOOL *, RIPEMInfo *));
char *GetUserRecordFromFinger P((char *, char *, int, int *, RIPEMInfo *));

#undef P

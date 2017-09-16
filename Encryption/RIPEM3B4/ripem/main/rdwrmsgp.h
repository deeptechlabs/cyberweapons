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

#define ENCODE_CHUNKSIZE 48

char *CodeAndWriteBytes
  P((unsigned char *, unsigned int, char *, FILE *));
char *BufferCodeAndWriteBytes
  P((unsigned char *, unsigned int, char *, BufferStream *));
void WriteCoded P((unsigned char *, unsigned int, char *, FILE *));
char *WriteEOL P((BufferStream *));

#undef P



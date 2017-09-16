/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/* Use conditional compile so header file is only included once */
#ifndef _BFSTREAM_H_
#define _BFSTREAM_H_ 1

#ifdef __STDC__
# define  P(s) s
#else
# define P(s) ()
#endif

typedef struct {
  unsigned char *buffer;
  /* point points to the first byte after the data in buffer.  It is
       incremented as data is written to buffer and gives the length
       of the valid data. */
  unsigned int point;
  unsigned int maxBufferLen;                         /* Total size of buffer */
} BufferStream;

void BufferStreamConstructor P((BufferStream *));
void BufferStreamDestructor P((BufferStream *));
char *BufferStreamWrite P((unsigned char *, unsigned int, BufferStream *));
char *BufferStreamPuts P((char *, BufferStream *));
char *BufferStreamPutc P((int, BufferStream *));
void BufferStreamRewind P((BufferStream *));
void BufferStreamFlushBytes P((BufferStream *, unsigned int));
void BufferStreamUnput P((BufferStream *, unsigned int));

#undef P

#endif

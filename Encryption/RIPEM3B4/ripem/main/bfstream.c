/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "bfstream.h"

#define BUFFER_SIZE_SLACK 1024

/* Initialize the buffer stream so that writes will reallocate the
     buffer as necessary.
 */
void BufferStreamConstructor (stream)
BufferStream *stream;
{
  stream->buffer = (unsigned char *)NULL;
  stream->maxBufferLen = 0;
  stream->point = 0;
}

/* Zeroize and free the buffer.
 */
void BufferStreamDestructor (stream)
BufferStream *stream;
{
  if (stream->buffer != (unsigned char *)NULL) {
    R_memset ((POINTER)stream->buffer, 0, stream->maxBufferLen);
    free (stream->buffer);
  }
}

/* Copy block to stream's buffer at the point given by stream->point and
     update point for more writes.  This resizes the buffer as needed
     by allocating a new one, copying, zeroizing and freeing the old one.
     We don't use realloc since this will leave sensitive data lying
     around.
   If block is (unsigned char *)NULL, then this will still resize the stream's
     buffer to hold blockLen more bytes, but not write anything there.
   This returns an error if blockLen bytes would overflow a buffer whose
     size is given by unsigned int.     
   Return NULL for success or error string for error.
 */
char *BufferStreamWrite (block, blockLen, stream)
unsigned char *block;
unsigned int blockLen;
BufferStream *stream;
{
  unsigned int newSize, newPoint;
  unsigned char *newBuffer;
  
  /* Set newPoint to point+blockLen and test it this is
       less than point or blockLen.  Presumably if it is then we
       had an overflow of the unsigned int. */
  newPoint = stream->point + blockLen;
  if (newPoint < stream->point || newPoint < blockLen)
    return ("Buffer size overflow in BufferStreamWrite");

  if (newPoint > stream->maxBufferLen) {
    /* Resize the buffer to accomodate the bytes being written.
       Also allocate some extra bytes if possible to allow more writes
         before another realloc.
     */
    newSize = newPoint + BUFFER_SIZE_SLACK;
    if (newSize < newPoint || newSize < BUFFER_SIZE_SLACK)
      /* The newSize including the slack overflows, so skip the slack
           and allocate only exactly what we need (which we have already
           made sure doesn't overflow. */
      newSize = newPoint;
    if ((newBuffer = (unsigned char *)malloc (newSize))
        == (unsigned char *)NULL)
      return (ERR_MALLOC);

    /* Copy and zeroize and free the old buffer.
     */
    R_memcpy ((POINTER)newBuffer, (POINTER)stream->buffer, stream->point);
    R_memset ((POINTER)stream->buffer, 0, stream->maxBufferLen);
    free (stream->buffer);
    stream->buffer = newBuffer;
    stream->maxBufferLen = newSize;
  }

  if (block != (unsigned char *)NULL)
    memcpy (stream->buffer + stream->point, block, blockLen);
  stream->point = newPoint;

  return ((char *)0);
}

/* Write the string to stream's buffer (without end of line).
 */
char *BufferStreamPuts (string, stream)
char *string;
BufferStream *stream;
{
  return (BufferStreamWrite
          ((unsigned char *)string, strlen (string), stream));
}

/* Convert the character to a char and write it to stream's buffer.
 */
char *BufferStreamPutc (c, stream)
int c;
BufferStream *stream;
{
  char block[1];

  block[0] = (char)c;
  return (BufferStreamWrite ((unsigned char *)block, 1, stream));
}

/* Rewind the stream by setting the point back to zero.
 */
void BufferStreamRewind (stream)
BufferStream *stream;
{
  stream->point = 0;
}

/* Get rid of the first count bytes at the beginning of the steram's
     buffer by shifting the buffer back.  This readjusts point to
     reflect the shorter buffer length.  If count is >= point, this
     sets the buffer length to zero.
 */
void BufferStreamFlushBytes (stream, count)
BufferStream *stream;
unsigned int count;
{
  unsigned int i;
  unsigned char *from, *to;
  
  if (count >= stream->point) {
    stream->point = 0;
    return;
  }

  /* Set point to the new buffer length */
  stream->point -= count;

  /* Shift the buffer */
  to = stream->buffer;
  from = stream->buffer + count;
  for (i = stream->point; i > 0; --i)
    *(to++) = *(from++);
}

/* This decreases the length of the stream's buffer by count.  If
     count is too long, the length of the buffer is set to zero.
   This is useful for adjusting the length of the buffer after allocating
     too many bytes using BufferStreamWrite.
 */
void BufferStreamUnput (stream, count)
BufferStream *stream;
unsigned int count;
{
  if (count >= stream->point)
    stream->point = 0;
  else
    stream->point -= count;
}

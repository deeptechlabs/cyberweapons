/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- File pubinfo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "headers.h"
#include "keyfield.h"
#include "pubinfop.h"
#include "protserv.h"
#include "strutilp.h"

#define LINEBUFSIZE 200
#define LINELEN 240

/*--- function ReadUserRecord --------------------------------------------
 *
 *  Read key information for a user, from a flat file.
 *  Records for different users are demarcated by any of:
 *    Blank line
 *    Line starting with '-'
 *    End of file
 *    
 *  Entry:  stream  is positioned at the beginning of a user record.
 *        maxLen  is the size of rec.
 *
 *  Exit:   rec     points to the user record read in from the file.
 *                  It is terminated by a zero byte.
 *        dataLen  is the number of bytes in the record.
 *        Returns TRUE upon success.
 */
int
ReadUserRecord(stream,rec,maxLen,dataLen)
FILE *stream;
char *rec;
int maxLen;
int *dataLen;
{
#define RECSIZE 512
  char line[RECSIZE];
  char *cptr = rec, *lptr;
  int first=1;

  *dataLen = 0;
  while(1) {
    if(!fgets(line,RECSIZE,stream)) break;
    /* At the beginning, skip past blank lines and -----BEGIN */
    if(first) {
      if(LineIsWhiteSpace(line) || strncmp(line,"-----BEGIN",10)==0) {
        continue;
      } else {
        first = 0;
      }
    }
    if(!first) {
      /* Within the record, a blank line or -----END terminates. */
      if(LineIsWhiteSpace(line)) break;
      if(strncmp(line,"-----END",8)==0) break;
      /* Copy this line into the buffer */
      for(lptr=line; *lptr; lptr++) {
        if(!(maxLen--)) {
          return 0;
        }
        *(cptr++) = *lptr;
      }     
    } 
  }   
  *cptr = '\0';
  *dataLen = cptr - rec + 1;
  return cptr != rec;
}

/* Scan a user record to find if it contains info for a given user.
   We are looking for a "User: " field with a given value.
 
   Entry:  user    is the email address of a user.
         userRec is a zero-terminated buffer of lines.
 
   Exit: Sets *found to TRUE if the desired user is found, else FALSE.
   Returns NULL for success, otherwise error string.
 */
char *FindUserInRecord (found, user, userRec)
BOOL *found;
char *user;
char *userRec;
{
  char *cptr = userRec, *temp_buf;

  /* Allocate on heap since it is too big for the stack */
  if ((temp_buf = (char *)malloc (LINELEN)) == (char *)NULL)
    return (ERR_MALLOC);

  *found = FALSE;

  while (1) {
    if (!CrackKeyField (cptr, USER_FIELD, temp_buf, LINELEN))
      /* No more "User:" fields.
       */
      break;
    else {
      if (!EmailMatch (user, temp_buf)) {
        /* This User: line indicates a different user. 
         * Look to see if there's another User: line.
         */
        if (!NextLineInBuf (&cptr))
          continue;
      }
      else {
        /* We have found the user's key.  All OK. */
        *found = TRUE;
        break;
      }
    }
  }

  free (temp_buf);
  return ((char *)NULL);
}

/* Position the input file to just after a given field name.  This only
     checks the beginning of the file lines up to the length of fieldName.
   This returns FALSE if it reads a blank line.
 
   Entry:  stream   is the input file to search.
           fieldName    is the name of the field to search for.
           copyStream  If not null, write every line read from stream
             to copyStream.  This is useful when copying a file in
             order to replace the field associated with fieldName.
 
   Exit:   Returns TRUE if the field is found, else FALSE.
           If TRUE, the input stream is positioned just after the line
             containing the field name.  If FALSE, the input is positioned
             after the blank line or at the end of file.
 */
BOOL PosFileLine (stream, fieldName, copyStream)
FILE *stream;
char *fieldName;
FILE *copyStream;
{
  char line[LINEBUFSIZE];
  int fieldNameLen = strlen (fieldName);

  while (fgets (line, LINEBUFSIZE, stream)) {
    if (copyStream != (FILE *)NULL)
      fputs (line, copyStream);

    if (strncmp (line, fieldName, fieldNameLen) == 0)
      return(TRUE);

    if (LineIsWhiteSpace (line))
      return (FALSE);
  }

  return(FALSE);
}

/*--- function GetFileLine ---------------------------------------------
 *
 *  Search an input stream for a line starting with a given field name,
 *  and return the rest of that line.
 *  Lines are formatted as described in PosFileLine.
 *
 *  Entry   stream   is the input stream.
 *          field    is the text of the field (including trailing
 *                   colon if applicable).
 *          valuelen is the maximum number of bytes that can fit in "value".
 *
 *  Exit    value    is the rest of the line, not including the
 *                   name of the field and the intervening white space.
 *          Returns TRUE if the field was found, else FALSE.
 */
BOOL
GetFileLine(stream,field,value,valuelen)
FILE *stream;
char *field;
char *value;
int valuelen;
{
  char line[LINEBUFSIZE], *cptr;
  int fieldlen = strlen(field);

  while(fgets(line,LINEBUFSIZE,stream)) {
    if(strncmp(line,field,fieldlen)==0) {
      cptr = line+fieldlen;
      while(WhiteSpace(*cptr) && *cptr) cptr++;
      fieldlen = strlen(cptr);
      if(cptr[fieldlen-1]=='\n') cptr[fieldlen-1] = '\0';
      strncpy(value,cptr,valuelen);
      return (TRUE);
    }
  }
  return(FALSE);
}


/*--- function ExtractValue -------------------------------------------------
 *
 *  Extract the value of a field.
 *
 *  Entry:  bptr    points to a buffer containing a "name: value" field.
 * 
 *  Exit: 
 */
int
ExtractValue(bptr,val,maxLen)
char *bptr;
char *val;
unsigned int maxLen;
{
  while(*bptr && *bptr != ':') bptr++;
  if(*bptr) bptr++;

  while(*bptr && (*bptr == ' ' || *bptr == '\t')) bptr++;

  while(isprint(*bptr) && maxLen--) {
    *(val++) = *(bptr++);
  }
  *val = '\0';
  
  return 1;
}

/*--- function CrackKeyField ---------------------------------------------
 *
 *  Search a buffer for a field.
 *  The buffer contains fields consisting of field names followed by
 *  field values.  A buffer looks like:
 *
 *  name1: value1\n
 *  name2: value2\n
 *    more value2... \n
 *  name3: \n
 *    value3...
 *
 *  In other words, a value can span several lines.  Continuation lines are
 *  indicated by a space right after a newline.
 * 
 *  Entry:  bptr    points to a buffer containing key info for a user.
 *              The buffer is zero-terminated.
 *        field    is name of the field we are looking for, zero-terminated.
 *              If field is NULL, we make no attempt to position bptr.
 *        valSize is the size of the val buffer.
 *  
 *   Exit:  val       contains the value of the field, zero-terminated.
 *              Embedded newlines have been removed.
 *        Returns TRUE if the field was found.
 */
int
CrackKeyField(bptr,field,val,valSize)
char *bptr;
char *field;
char *val;
int   valSize;
{
  int fieldlen = strlen(field);
  
  if(field) {
    /* Find the field with the proper name. */
    while(strncmp(bptr,field,fieldlen) != 0) {
      /* This isn't it.  Skip to the next line. */
      while(*bptr && *bptr != '\n') bptr++;
      /* Return failure if we didn't find the fieldname (no next line). */
      if(!*bptr) return FALSE;
      bptr++;  /* Skip past EOL */
    }
    bptr += fieldlen;
  }
  
  /* Copy lines (skipping leading white space) to val, until we
   * come to a line that doesn't start with white space. 
   */
  do {
    /* Skip leading white space */
    while(*bptr && (*bptr==' ' || *bptr == '\t')) bptr++;
    
    /* Copy to end of line */
    while(valSize && *bptr != '\n' && *bptr!='\r' && *bptr) {
      *(val++) = *(bptr++);
      valSize--;
    }
    /* Skip past EOL */
    while(*bptr == '\n' || *bptr=='\r') bptr++;
    /* Keep going as long as following lines start with blanks */
  } while(*bptr && (*bptr == ' ' || *bptr == '\t'));
  *val = '\0';

  return 1;
}

/*--- function GetPubInfoFromFile -----------------------------------------
 *
 *  Read a key record from a flat file into a buffer, collapsing multiple
 *  continuation lines into one long line where necessary.
 *
 *  This routine is unused.
 *  
 */
int
GetPubInfoFromFile(stream,buf,bufLen,returnedLen)
FILE *stream;
char *buf;
unsigned int bufLen;
unsigned int *returnedLen;
{
#define ADDBYTE(cha)              \
    if(bufLen-- == 0) return 1;     \
    (*buf++) = cha;             \
    (*returnedLen)++;

  int ch;

  *returnedLen=0;

  /* Skip past leading blank lines. */
  while(EOF != (ch=getc(stream)) && ch == '\n');

  do {
    if(ch == EOF) return 1;
    /* Add the contents of this line, up to but not including the
     * newline, to the buffer.
     */
    do {
      ADDBYTE(ch);
      ch = getc(stream);
    } while(EOF!=ch && ch != '\n');

    /* If the next line is blank, we've reached the end of the entry.
     * If it starts with white space, it's a continuation of this line.
     * Otherwise, we start a new line.
     */
    ch = getc(stream);
    if(ch == '\n') {
      ADDBYTE('\n');
      ADDBYTE('\0');
      return 0;
    } else if(EOF == ch) {
      return 1;
    }
    if(ch!=' ' && ch!='\t') {
      ADDBYTE('\n');
    }
  } while(1);
}

/*--- function NextLineInBuf -------------------------------------------
 */
int
NextLineInBuf(buf)
char **buf;
{
  int gotone = 0;

  while(**buf && **buf!='\n' && **buf!='\r') (*buf)++;
  if(**buf == '\r') (*buf)++;
  if(**buf == '\n') (*buf)++;
  if(**buf) gotone = 1;
  
  return gotone;
}

/*--- function ExtractPublicKeyLines ------------------------------------------
 *
 *  Extract the public key info (bounded by lines of 
 *  -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----)
 *  from one buffer to another.
 *
 *  Entry:  inBuf   is a buffer containing lines delimited by LF or
 *              CR/LF.  It's zero-terminated.
 *        outSize is the number of bytes in outbuf (max).
 *        
 *   Exit:   outBuf contains the lines between the above delimiters,
 *              if found.
 *        Returns TRUE if found.
 */
BOOL ExtractPublicKeyLines(inBuf,outBuf,outSize)
char *inBuf;
char *outBuf;
int outSize;
{
  char *begptr;
  int nbytes;
  
  while (strncmp (inBuf, PUB_KEY_STRING_BEGIN, PUB_KEY_STRING_BEGIN_LEN) != 0) {
    if (!NextLineInBuf (&inBuf))
      return (FALSE);
  }
  NextLineInBuf (&inBuf);
  begptr = inBuf;
  
  while (strncmp (inBuf, PUB_KEY_STRING_END, PUB_KEY_STRING_END_LEN) != 0) {
    if (!NextLineInBuf (&inBuf))
      return (FALSE);
  }
  
  nbytes = inBuf - begptr > outSize ? outSize : inBuf - begptr;
  strncpy (outBuf, begptr, nbytes);
  
  return (TRUE);  
}

/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*-- bemparse.c -- Routines to parse a data structure
 *  in OSI's Basic Encoding Rules format.
 *
 *  Basic Encoding Rules (BEM) specify a means of encoding
 *  a complex data structure as a string of "octets" (bytes).
 *  The routines here display a data structure represented
 *  via BEM, breaking down the data structure into its
 *  constituent parts.  (Abstract Syntax Notation refers
 *  to these data structures as "types".)
 *
 *  These routines were written to facilitate experimentation/
 *  development of a Privacy Enhanced Mailer, and by no
 *  means can parse all possible BEM data structures.
 *
 *  Information used to develop these routines was gleaned
 *  from the Public-Key Cryptography Standards documents
 *  and other documents available via FTP to RSA.COM.
 *
 *  Placed in the public domain.
 *
 *  Mark Riordan   7 May 1992
 */

#include <stdio.h>
#include <errno.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "bemparse.h"

#ifdef mips
extern int errno;
#endif

/* Symbols for the Tag field of a type. */

#define TAG_INTEGER             0x02
#define TAG_BIT_STRING          0x03
#define TAG_OCTET_STRING        0x04
#define TAG_NULL                0x05
#define TAG_OBJECT_IDENTIFIER   0x06
#define TAG_SEQUENCE            0x10
#define TAG_SET                 0x11
#define TAG_PrintableString     0x13
#define TAG_IA5String           0x16
#define TAG_UTCTime             0x17

#define TAG_MASK                0x1f
#define TAG_HIGH_BASE           0x80

/* Bit mask to isolate the "constructed" bit. */

#define CONSTRUCTED_MASK        0x20

/* Symbols for the Class field of a type. */

#define CLASS_MASK             0x03
#define CLASS_Universal        0x00
#define CLASS_Application      0x01
#define CLASS_Context_Specific 0x02
#define CLASS_Private          0x03
#define CLASS_SHIFT            6

#define LENGTH_MASK            0x80

#define OBJECT_BASE            128


typedef int TypeClass;
typedef long int TypeTag;
typedef int      TypeConstructed;

typedef unsigned char octet;

/* Here are some data structures used by the program
 * to identify the various types and classes, and to map
 * the binary representation to ASCII strings that
 * describe them.
 */

struct struct_tag {
  TypeTag      tagcode;
  char        *tagname;
} tagCodes[] = {
  {TAG_INTEGER, "INTEGER"},
  {TAG_BIT_STRING, "BIT_STRING"},
  {TAG_OCTET_STRING, "OCTET_STRING"},
  {TAG_NULL, "NULL"},
  {TAG_OBJECT_IDENTIFIER, "OBJECT_IDENTIFIER"},
  {TAG_SEQUENCE, "SEQUENCE"},
  {TAG_SET, "SET"},
  {TAG_PrintableString, "PrintableString"},
  {TAG_IA5String, "IA5String"},
  {TAG_UTCTime, "UTCTime"} 
};

struct struct_class {
  TypeClass    classcode;
   char        *classname;
} classCodes[] = {
  {CLASS_Universal, "Universal"},
  {CLASS_Application, "Application"},
  {CLASS_Context_Specific, "Context_Specific"},
  {CLASS_Private, "Private"} };

static TypeLength ParseID
  P((unsigned char **, TypeClass *, TypeConstructed *, TypeTag *));
static TypeLength BEMParse2 P((unsigned char **, FILE *, int *));
static void ParseSequence P((unsigned char **, TypeLength, FILE *, int *));
static TypeLength ParseLength P((octet **, TypeLength *));
static void PutIndent P((FILE *, int));

/*--- function BEMParse ---------------------------------
 *
 * Parse a BEM type, writing a description to standard output.
 *
 * Entry:   octstr   is a "binary" string of bytes representing
 *                   a BEM type.
 *        stream  is the stream to write to.
 *
 * Exit:    A human-readable description has been written
 *            to output.
 *        Returns the number of bytes in the type.
 */

TypeLength
BEMParse(octstr,stream)
unsigned char *octstr;
FILE *stream;
{
  int indent_level;

  indent_level=0;
  return BEMParse2(&octstr, stream, &indent_level);
}

/*--- function BEMParse2 --------------------------------
 *
 * Do the real work of BEMParse.  It's a separate routine
 * to allow recursion.
 *
 * Entry: octstr  points to a string of octets.
 *
 * Exit:    octstr   points to the end of the string.
 *        Returns the number of bytes in the type.
 *          A description has been written to output.
 */

static TypeLength
BEMParse2(octstr, bstream, indent_level)
unsigned char **octstr;
FILE *bstream;
int *indent_level;
{
  octet *octptr = *octstr;
  TypeClass  class;
  TypeTag    tag;
  TypeLength length;
  TypeLength idlen, lenlen, totlen, val;
  int j, found, constructed;
  int idx = 0;

  idlen = ParseID(octstr,&class,&constructed,&tag);

  lenlen = ParseLength(octstr,&length);

  totlen = idlen + lenlen + length;

  PutIndent(bstream, *indent_level);
  if(constructed) {
    fprintf(bstream,"Constructed ");
  }

  /* Describe the class. */

  for(j=0, found=0; !found && j<sizeof(classCodes) /
      sizeof(classCodes[0]); j++) {
    if(class == classCodes[j].classcode) {
      found = 1;
      idx = j;
    }
  }

  fprintf (bstream,"%s ",found ? classCodes[idx].classname : "Bad class");

  /* Describe the type.  If it's not Universal class, I
   * won't know much about it.
   */

  for(j=0, found=0; !found && j<sizeof(tagCodes) /
      sizeof(tagCodes[0]); j++) {
    if(tag == tagCodes[j].tagcode) {
      found = 1;
      idx = j;
    }
  }

  fprintf(bstream,"%s ",found ? tagCodes[idx].tagname : "Unknown tag");

  if(constructed) {
    fprintf(bstream,":\n");
    ParseSequence(octstr,length, bstream, indent_level);
  } else {

    switch(tag) {
    case TAG_SET:
    case TAG_SEQUENCE:
      fprintf(bstream,"\n");
      ParseSequence(octstr,length, bstream, indent_level);
      break;
      
    case TAG_INTEGER:
    case TAG_OCTET_STRING:
    case TAG_BIT_STRING:
      if(length > 3 || 1) {
        int chperline=0;
        
        putc('\n',bstream);
        for(j=0; j<length; j++) {
          if(chperline == 0) {
            PutIndent(bstream, *indent_level);
            fputs("   ",bstream);
          }
          fprintf(bstream,"%-2.2x ",*(*octstr+j));
          if(++chperline >= 16) {
            putc('\n',bstream);
            chperline = 0;
          }
        }
        if(chperline) putc('\n',bstream);
      } else {
        val = 0;
        for(j=0; j<length; j++) {
          val = val*256 + *(*octstr+j);
        }
        fprintf(bstream,"%ld\n",val);
      }
      *octstr += (int)length;
      break;

    case TAG_UTCTime:
      /* I think this is a date in YYMMDDHHMMSS format--very strange
       * that it's not Year 2000-compliant.   mrr 1997/05/31
       */
      for(j=0; j<length; j++) {
         putc(*(*octstr+j),bstream);
         if(j%2) putc(' ',bstream);
      }
      putc('\n',bstream);
      *octstr += (int)length;
      break;
      
    case TAG_IA5String:
    case TAG_PrintableString:
      for(j=0; j<length; j++) putc(*(*octstr+j),bstream);
      putc('\n',bstream);
      *octstr += (int)length;
      break;
      
    case TAG_OBJECT_IDENTIFIER:
      octptr = *octstr;
      val = *octptr / 40;
      fprintf(bstream,"%ld ",val);
      val = *octptr % 40;
      fprintf(bstream,"%ld ",val);
      octptr++;
      while(octptr < *octstr + (int)length) {
        for(val=0; *octptr & OBJECT_BASE; octptr++) {
          val = val*OBJECT_BASE + ((OBJECT_BASE-1) & *octptr);
        }
        val = val*OBJECT_BASE + *(octptr++);
        fprintf(bstream,"%ld ",val);
      }
      putc('\n',bstream);
      *octstr += (int)length;
      break;
      
    default:
      
      *octstr += (int)length;
      break;
    }
  }

  return totlen;
}

/*--- function ParseSequence ------------------------------
 *
 * Parse a structured type.
 *
 * Entry:   octstr  points to a string of bytes.  It is
 *              positioned at the first member of a
 *              sequence or constructed type.
 *        length  is the number of bytes in the sequence,
 *              not including the header after which
 *              octstr is positioned.
 *        *indent_level specifies how deep we are down in
 *              the data structure.
 *
 *  Exit:    octstr   points right after the sequence.
 *        *indent_level is unchanged.
 *        A description of the entire sequence has been
 *          written out.
 */
static void
ParseSequence(octstr,length, bstream, indent_level)
unsigned char **octstr; 
TypeLength length;
FILE *bstream;
int *indent_level;
{
  TypeLength mylen;

  (*indent_level)++;
  do {
    mylen = BEMParse2(octstr, bstream, indent_level);
    length -= mylen;
  } while(length > 0);
  (*indent_level)--;
}

/*--- function ParseID ----------------------------------
 *
 * Parse the ID field of a BEM type.
 *
 * Entry: octstr  points to the beginning of a BEM type,
 *              which is where the ID bytes are.
 *
 *  Exit:   octstr  points to just beyond the ID bytes.
 *          class   is the class of the type.
 *        constructed is non-zero if the type is constructed.
 *        tag   is the tag of the type.
 *        Returns the number of bytes in the ID field.
 */
static TypeLength
ParseID(octstr,class,constructed,tag)
unsigned char **octstr; 
TypeClass *class;
TypeConstructed *constructed;
TypeTag *tag;
{
  octet *octptr = *octstr;
  TypeLength IDlen;

  *class = (*octptr >> CLASS_SHIFT) & CLASS_MASK;
  IDlen = 1;

  *constructed = *octptr & CONSTRUCTED_MASK;

  if((TAG_MASK & *octptr) == TAG_MASK) {
    /* This is High-tag-number form */
    *tag = 0;
    for(octptr++; TAG_HIGH_BASE & *octptr; octptr++) {
      *tag *= TAG_HIGH_BASE;
      *tag += *octptr - TAG_HIGH_BASE;
      IDlen++;
    }
    *tag *= TAG_HIGH_BASE;
    *tag += *octptr;
    IDlen++;
  } else {
    *tag = *octptr & TAG_MASK;
  }

  *octstr = octptr+1;
  return IDlen;
}

/*--- function ParseLength ----------------------------------
 *
 *  Parse the Length field of a BEM type.
 *
 *  Entry:  octstr  points to the beginning of the length
 *              field of a BEM type.
 *
 *  Exit:    length   is the extracted value of the length field.
 *        Returns the number of bytes in the length field.
 */
static TypeLength
ParseLength(octstr,length)
octet **octstr; 
TypeLength *length;
{
  octet *octptr = *octstr;
  int lenbytes;
  TypeLength Lenlen;

  if(*octptr & LENGTH_MASK) {
    /* Long form of length. */
    lenbytes = *octptr & (LENGTH_MASK-1);
    Lenlen = lenbytes+1;
    for(*length=0,octptr++; lenbytes; lenbytes--,octptr++) {
      *length = *length*256 + *octptr;
    }
  } else {
    *length = *octptr;
    Lenlen = 1;
    octptr++;
  }

  *octstr = octptr;
  return Lenlen;
}

/*--- function PutIndent ----------------------------------
 *
 *  Indent the output to reflect how deeply nested the
 * BEM type is at this point.
 *
 *  Entry:  *indent_level is the number of levels of nesting
 *         at the current point in the BEM string.
 *         0 means no nesting (e.g., the whole BEM string
 *         is just a simple type).
 *
 *  Exit:   Spaces have been written to output to indent
 *         the line about to be written.
 */

static void
PutIndent(bstream, indent_level)
FILE *bstream;
int indent_level;
{
  int j;

  for(j=0; j<indent_level; j++) fprintf(bstream,"   ");
}

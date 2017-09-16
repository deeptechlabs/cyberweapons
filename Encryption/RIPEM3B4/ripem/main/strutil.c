/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- file strutil.c -- string-oriented utilities.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "strutilp.h"
#include "hexbinpr.h"

/*  Determine whether two character strings match.  Case insensitive.
 *
 *  Entry:  str      is a string.
 *      pattern  is a pattern to which we are comparing.
 *
 *  Exit:   Returns TRUE iff the strings match.
 */
int R_match(str,pattern)
char *str;
char *pattern;
{
  char ch1, ch2;

  do {
    ch1 = (char) (islower(*str) ? toupper(*str) : *str);
    ch2 = (char) (islower(*pattern) ? toupper(*pattern) : *pattern);
    if(ch1 != ch2) return FALSE;
    str++; pattern++;
  } while(ch1 == ch2 && ch1 && ch2);
  
  if(!ch1 && !ch2) {
    return TRUE;
  } else {
    return FALSE;
  }
}

/*--- function WhiteSpace -------------------------------------------
 *
 *  Determine whether a character is "white space".
 *
 *  Entry:  ch    is a character.
 *
 *  Exit:   Returns TRUE iff the character is "white space".
 */
int
WhiteSpace(ch)
int ch;
{
  return(ch==' ' || ch=='\t' || ch=='\n');
}

/*--- function LineIsWhiteSpace --------------------------------
 *
 *  Determine whether an entire line is nothing but white space.
 *
 *  Entry:  line  points to a zero-terminated line.
 *
 *   Exit:   Returns TRUE if line has nothing but white space
 *         prior to the EOL.
 */
BOOL
LineIsWhiteSpace(line)
char *line;
{
  for(; *line; line++) {
    if(!WhiteSpace(*line)) return FALSE;
  }
  return TRUE;
}

/*--- function strcpyalloc -------------------------------------
 *
 *  Copy a string, allocating space for it.
 *
 *   Entry: target points to a pointer to a character.
 *        source points to z zero-terminated string that
 *       we want to copy.
 *
 *  Exit: target contains a pointer to a newly-allocated
 *               piece of memory that contains a copy of
 *             source.
 *        Returns NULL if alloc unsuccessful, else
 *          returns target.
 */
char *
strcpyalloc(target,source)
char **target;
char *source;
{
  *target = (char *) malloc(strlen(source)+1);
  if(*target) {
    strcpy(*target,source);
  }
  return *target;
}

/*--- function strcatrealloc ------------------------------
 *
 *  Append a string to another string, reallocating memory
 *  for the target string to ensure there's room.
 *
 *  Entry:  target points to a pointer to a string to
 *             be appended to.
 *        source points to a string to append.
 *
 *   Exit:  target now points to a possibly different address,
 *             a pointer to the combined string.
 */
char *strcatrealloc (target,source)
char **target;
char *source;
{
  *target = (char *)R_realloc
    (*target, strlen (source) + strlen (*target) + 1);
  if (*target) {
    strcat (*target, source);
  }
  return *target;
}


/*  Trim trailing white space from a line.
 *
 *  Entry:  line  points to a zero-terminated line.
 *
 *  Exit:   Any trailing white space (including newlines) has
 *         been eliminated.
 */
void R_trim(line)
char *line;
{
  char *cptr = line + strlen(line) - 1;

  while(cptr >= line && WhiteSpace(*cptr)) *(cptr--) = '\0';
}

/*--- function ExtractEmailAddr ----------------------------------------------
 *
 *  Extract the proper email address from a line *containing* an
 *  email address, often a line that was part of a "From:" line
 *  in another email address.
 *  For instance, we may receive lines like:
 *
 *  rstevens@noao.edu (W. Richard Stevens)
 *    "Mark Riordan" <riordanmr@clvax1.cl.msu.edu>
 *    person@cps.msu.edu
 *
 *  and we need to figure out which characters constitute the
 *  email address.
 *
 *  Entry:  addr    is an electronic mail address, possibly with
 *              extra characters as above.
 *
 *   Exit:  Returns a pointer to the correct substring of above.
 *        May modify the contents of "addr".
 */
char *
ExtractEmailAddr(addr)
char *addr;
{
  char search_char='\0', *cptr;
  
  R_trim(addr);
  
  cptr = addr + strlen(addr) - 1;
  /* Look at the last character of addr */
  if(*cptr == '>') {
    /* Extract what's between < ... > */
    search_char = '<';
    *cptr = '\0';
    while(*cptr != search_char && cptr != addr) cptr--;
    if(*cptr == search_char) cptr++;
    return cptr;
    
  } else if(*cptr == ')') {
    /* Strip the trailing "(Firstname Lastname)" from addr */
    search_char = '(';
    *cptr = '\0';
    while(*cptr != search_char && cptr != addr) {
      cptr--;
    }
    if(*cptr == search_char) *cptr = '\0';
    R_trim(addr);
  }
  
  return addr;
}

/*--- function BreakUpEmailAddr --------------------------------------------
 *
 *  Break an Internet-style email address into username and hostname.
 *
 *  Entry:  addr    is an address of form user@hostname.domain
 *        lenUser and lenHost are the number of bytes in the respective
 *              buffers.
 *  
 *   Exit:  userName  is the username (zero-terminated).
 *        hostName is the hostname.
 *        Returns NULL upon success, else error message.
 */
char *
BreakUpEmailAddr(addr,userName,lenUser,hostName,lenHost)
char *addr;
char *userName;
int lenUser;
char *hostName;
int lenHost;
{
  char *cptr;
  int addrlen = strlen(addr), hostlen, nbytes;
  
  cptr = strchr(addr,'@');
  if(!cptr) {
    return "Email address is not in Internet format";
  } else {
    nbytes = lenUser>cptr-addr ? cptr-addr : lenUser-1;
    strncpy(userName,addr,nbytes);
    userName[nbytes] = '\0';
    hostlen = addr + addrlen - (cptr+1); 
    nbytes = lenHost>hostlen ? hostlen : lenHost-1;
    strncpy(hostName,cptr+1,nbytes);
    hostName[nbytes] = '\0';
  }
  return NULL;
}

/*--- function EmailHostnameComponents ------------------------------------
 *
 *  Calculate the number of components in the hostname portion
 *  of an Internet-style email address.
 *  E.g.,  bill@cs.bigu.edu  has 3 hostname components.
 *
 *   Entry: user  is an email address.
 *
 *   Exit:   Returns number of components.
 */

int
EmailHostnameComponents(addr)
char *addr;
{
  int ncomp = 0;
  char *cptr;

  cptr = strchr(addr,'@');
  if(cptr) {
    cptr++;
    ncomp = 1;
    while(*cptr) if(*(cptr++)=='.') ncomp++;
  }
  return ncomp;
}

/*--- function EmailAddrUpALevel -------------------------------------
 *
 *  Modify an Internet email address to remove the first component
 *  of its hostname.
 *  E.g., bill@cs.bigu.edu --> bill@bigu.edu
 *
 *   Entry: addr  is an email address.
 *
 *  Exit: addr  has been modified.
 *        Returns TRUE if we were able to complete processing.
 */
int
EmailAddrUpALevel(addr)
char *addr;
{
  char *cptr, *targ;
  
  if(EmailHostnameComponents(addr) < 3) return FALSE;

  targ = cptr = strchr(addr,'@')+1;
  for(; *cptr && *cptr!='.'; cptr++);  /* Skip past first level */
  for(cptr++; *cptr; ) *(targ++) = *(cptr++);  /* Copy rest */
  *targ = '\0';

  return TRUE;
}

/*--- function EmailMatch --------------------------------------
 *
 *  Determine whether a given email addresses matches a known address
 *  of a user.  Simply requires that the two usernames
 *  match and that the hostnames match, minus the first few
 *  components of the hostname.
 *
 *  Entry:  user      is the known email address.
 *        candidate   is an address that may match.
 *
 *   Exit:   Returns TRUE iff the two correspond.
 */
BOOL
EmailMatch(user, candidate)
char *user;
char *candidate;
{
  char *user_copy;
  BOOL trying=TRUE;
  BOOL matchOK=FALSE;

  strcpyalloc(&user_copy,user);  /* We may modify user_copy below */

  /* Keep testing for a case-insensitive both otherwise exact
   * lexicographical match while we remove successive leftmost
   * components from the hostname of the candidate.
   */
  do {
    if(R_match(user_copy,candidate)) {
      trying = FALSE;
      matchOK = TRUE;
    } else {
      trying = EmailAddrUpALevel(user_copy);
    }
  } while(trying); 
  
  free(user_copy);
  return matchOK;
}

/*--- function LowerCaseString --------------------------------------------
 *
 *  Convert an entire string to lowercase.
 *
 *  Entry:  str is the address of a xero-terminated string.
 *
 *   Exit:  All of the alphabetic characters in the string have 
 *        been converted to lowercase.
 *        Returns the address of the string.
 */
char *
LowerCaseString(str)
char *str;
{
  register char ch, *addr=str;

  while((ch = *addr) != 0) {
    if(isupper(ch)) *addr = tolower(ch);
    addr++;
  }
  return str;
}

/*--- function MakeHexDigest -------------------------------------------
 *
 *  Make an MD5 digest of the input, and return the result encoded
 *  into hex ASCII.
 */
void
MakeHexDigest(buf,buflen,hex_digest)
unsigned char *buf;
unsigned int buflen;
char *hex_digest;
{
  unsigned char digest[MD5_LEN];
  unsigned int digest_len;

  R_DigestBlock (digest, &digest_len, buf, buflen, DA_MD5);
  BinToHex (digest, MD5_LEN, hex_digest);
}


/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- Crackhed.c ---------------------------------------------------
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "headers.h"
#include "bfstream.h"
#include "crackhpr.h"
#include "strutilp.h"
#include "hexbinpr.h"
#include "derkeypr.h"
#include "certder.h"
#include "certutil.h"
#include "p.h"

static char *DoHeaderLine
  P((TypMsgInfo *, char *, RIPEMInfo *, RIPEMDatabase *));
static char *CrackHeaderLine P((char *, char *, unsigned int, TypList *));
static void TokenizeHeaderLine
  P((char *, char **, int, enum enum_fields *, enum enum_ids []));
static BOOL NameInList P((char *, TypList *));

void TypMsgInfoConstructor (messageInfo)
TypMsgInfo *messageInfo;
{
  messageInfo->got_orig_pub_key = FALSE;
  messageInfo->msg_key_len = 0;
  messageInfo->mic_len = 0;
  messageInfo->foundBeginBoundary = FALSE;
  messageInfo->doingHeader = TRUE;
  messageInfo->inEmailHeaders = TRUE;
  messageInfo->thisUser = FALSE;

  /* These are freed by the destructor. */
  messageInfo->orig_name = NULL;
  messageInfo->mic = (unsigned char *)NULL;
  messageInfo->msg_key = (unsigned char *)NULL;
  messageInfo->originatorCert = (unsigned char *)NULL;
  messageInfo->crlToInsert = (unsigned char *)NULL;
  BufferStreamConstructor (&messageInfo->extendedLine);
}

void TypMsgInfoDestructor (messageInfo)
TypMsgInfo *messageInfo;
{
  free (messageInfo->orig_name);
  free (messageInfo->mic);
  free (messageInfo->msg_key);
  free (messageInfo->originatorCert);
  free (messageInfo->crlToInsert);
  BufferStreamDestructor (&messageInfo->extendedLine);
}

/* Process a line from a PEM header, adding the info to messageInfo.
   This returns TRUE for doingHeader if there are more lines to process,
     or FALSE if the header has been all processed.

   Entry: messageInfo must have been initialized with TypMsgInfoConstructor.
   line is a null-terminated line from the incoming message.
     It may contain email headers, text before the begin PEM boundary
     or lines in the PEM header.  This will modify line by trimming
     trailing whitespace and other possible changes.
   If prependHeaders is TRUE, add email headers to headerList.  The calling
     routine must initialize headerList.
   This uses the publicKey in ripemInfo to check recipient identifier
     fields for the correct one.
   This also uses the userList in ripemInfo for Recipient-Name fields.
 
   Exit: Returns NULL if the line is process OK, else a pointer
     to an error message.
   When the blank line at the end of the PEM header is found, this
     returns FALSE in doingHeader, otherwise it returns TRUE in doingHeader.
     After finishing with messageInfo, the caller should call
     TypMsgInfoDestructor to free up its memory.
   Note: if the end of the input stream is found before this returns
     FALSE in doing header, it is an error.  If messageInfo->foundBeginBoundary
     is TRUE, and end of stream was unexpectedly found in the PEM header.
     If messageInfo->foundBeginBoundary is FALSE, then the begin PEM header
     boundary was not found.
 */
char *ProcessHeaderLine
  (ripemInfo, messageInfo, doingHeader, line, prependHeaders, headerList,
   ripemDatabase)
RIPEMInfo *ripemInfo;
TypMsgInfo *messageInfo;
BOOL *doingHeader;
char *line;
BOOL prependHeaders;
TypList *headerList;
RIPEMDatabase *ripemDatabase;
{
  char *cptr, *errorMessage;
  int mylen;

  /* Default to TRUE, set to FALSE when we read a blank line in the header. */
  *doingHeader = TRUE;

  /* Trim trailing whitespace. */
  R_trim (line);

  if (messageInfo->extendedLine.point != 0) {
    /* There is an extended line, so check if the line just read
         signals that is is complete. */

    if (!WhiteSpace (line[0]) || LineIsWhiteSpace (line) || strncmp
        (line, HEADER_STRING_END, HEADER_STRING_END_LEN) == 0) {
      /* We have the start of a new field, or we read a blank line or
           end boundary, so null terminate and process the extended line. */
      if ((errorMessage = BufferStreamPutc
           (0, &messageInfo->extendedLine)) != (char *)NULL)
        return (errorMessage);
      if ((errorMessage = DoHeaderLine
           (messageInfo, (char *)messageInfo->extendedLine.buffer, ripemInfo,
            ripemDatabase)) != (char *)NULL)
        return (errorMessage);
    }
  }

  if (!messageInfo->foundBeginBoundary) {
    /* We haven't hit the beginning message boundary yet. */
    if (strncmp (line, HEADER_STRING_BEGIN, HEADER_STRING_BEGIN_LEN) == 0)
      messageInfo->foundBeginBoundary = TRUE;
    else if (LineIsWhiteSpace (line))
      messageInfo->inEmailHeaders = FALSE;
    else if (prependHeaders && messageInfo->inEmailHeaders) {
      AppendLineToList (line, headerList);
    }
    else if (ripemInfo->debug > 2)
      fprintf(ripemInfo->debugStream,"Skipping: %s\n",line);
  }
  else {
    /* We are inside the PEM header. */
    if (LineIsWhiteSpace (line) || strncmp
        (line, HEADER_STRING_END, HEADER_STRING_END_LEN) == 0) {
      /* We have already processed any extended line.  Signal that
           we are done with the header and return. */
      *doingHeader = FALSE;
      return ((char *)NULL);
    }

    if (WhiteSpace (line[0])) {
      /* This is a continued line, so skip beginning whitespace and
           append to the extendedLine. */
      cptr = line;
      while (WhiteSpace (*cptr) && *cptr)
        cptr++;
      if ((errorMessage = BufferStreamPuts (cptr, &messageInfo->extendedLine))
          != (char *)NULL)
        return (errorMessage);
    }          
    else {
      /* We are at the beginning of a new line.  We have already
           processed any previous extended line.
         Add white space to the end of the field name on the
           first line of a field.  This space is used by the
           tokenizing routines to separate the field name from
           from the values.
       */
      mylen = strlen (line);
      /* We know mylen > 0 */
      if(line[mylen - 1] == ':') {
        /* This is a field name. */
        line[mylen] = ' ';
        line[mylen+1] = '\0';
      }

      /* Start a new extended line by rewinding */
      BufferStreamRewind (&messageInfo->extendedLine);
      if ((errorMessage = BufferStreamPuts
           (line, &messageInfo->extendedLine)) != (char *)NULL)
        return (errorMessage);
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream, "First line of field: \"%s\"\n",
                 line);
    }
  }

  return ((char *)NULL);
}

/* Parse the extendedLine and update messageInfo.
   This uses the publicKey in ripemInfo to check recipient identifier
     fields for the correct one.
 */
static char *DoHeaderLine (messageInfo, extendedLine, ripemInfo, ripemDatabase)
TypMsgInfo *messageInfo;
char *extendedLine;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
#define MAXVALS 4
  char *vals[MAXVALS];
  enum enum_fields tok_field;
  enum enum_ids tok_vals[MAXVALS];
  char fieldName[80];
  int nvals, j, mylen;
  char *errorMessage;
  TypList val_list;
  TypListEntry *entry;
  R_RSA_PUBLIC_KEY recipientPublicKey;
  int serialNumberLen;
  unsigned int binLen, derLen;
  unsigned char *bytes = (unsigned char *)NULL,
    serialNumber[MAX_SERIAL_NUMBER_LEN], alias[MD5_LEN], *bytesPointer;
  DistinguishedNameStruct *issuerName = (DistinguishedNameStruct *)NULL;

  InitList (&val_list);
  if ((errorMessage = CrackHeaderLine
       (extendedLine, fieldName, sizeof (fieldName), &val_list))
      != (char *)NULL)
    return (errorMessage);
  
  /* For error, break to end of do while (0) block. */
  do {
    for(j=0,entry=val_list.firstptr; entry&&j<MAXVALS; 
        entry=entry->nextptr,j++) {
      vals[j] = entry->dataptr;
    }
    nvals = j;
    if(ripemInfo->debug>1) {
      fprintf(ripemInfo->debugStream,"Field = \"%s\" [%d]",fieldName,
              strlen(fieldName));
      for(j=0; j<nvals; j++) {
        fprintf(ripemInfo->debugStream," \"%s\" [%d]",vals[j],strlen(vals[j]));
      }
      fputc('\n',ripemInfo->debugStream);
    }
    
    TokenizeHeaderLine(fieldName,vals,nvals,&tok_field,tok_vals);
    if(ripemInfo->debug>1) {
      int j;
      fprintf(ripemInfo->debugStream,"Field == type %d. Vals are types",
              tok_field);
      for(j=0; j<nvals; j++) {
        fprintf(ripemInfo->debugStream," %d",tok_vals[j]);
      }
      fprintf(ripemInfo->debugStream,".\n");
    }
    switch(tok_field) {
    case PROC_TYPE_ENUM:
      /* Look at Proc-Type number subfield (version). */
      if(tok_vals[0] != PROC_TYPE_RIPEM_ID_ENUM  &&
         tok_vals[0] != PROC_TYPE_PEM_ID_ENUM) {
        sprintf(ripemInfo->errMsgTxt,
                "RIPEM processes only Proc-Type %s and %s.",
                IDNames[PROC_TYPE_RIPEM_ID_ENUM],
                IDNames[PROC_TYPE_PEM_ID_ENUM]);
        errorMessage = ripemInfo->errMsgTxt;
        break;
      }

      /* Look at second Proc-Type subfield (encrypted vs. mic) */
      messageInfo->proc_type = tok_vals[1];
      if (messageInfo->proc_type < PROC_TYPE_ENCRYPTED_ID_ENUM ||
          messageInfo->proc_type > PROC_TYPE_CRL_ID_ENUM) {
        errorMessage = "Bad Proc-Type in message header.";
        break;
      }
      break;
    
    case CONTENT_DOMAIN_ENUM:
      /* Ignore Content-Domain */
      break;
      
    case RECIPIENT_ENUM:
      if (R_match (vals[0], GetDNSmartNameValue (&ripemInfo->userDN)) ||
          (ripemInfo->z.usernameAliases != (TypList *)NULL &&
           NameInList (vals[0], ripemInfo->z.usernameAliases))) {
        messageInfo->thisUser = TRUE;
        if (ripemInfo->debug > 1)
          fprintf(ripemInfo->debugStream,"(This recipient is you.)\n");
      }
      break;
      
    case RECIPIENT_KEY_ENUM:
      if (nvals != 1) {
        errorMessage = "Bad Recipient-Key-Asymmetric value.";
        break;
      }

      /* Decode the recipient public key and check if it is the user's.
       */
      binLen = DECRYPTED_CONTENT_LEN ((int)strlen (vals[0]));
      if ((bytes = (unsigned char *)malloc (binLen))
          == (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      /* CrackHeaderLine already strips leading and trailing blanks from
           values and null terminates. */
      /* Put output size in binLen, even though we don't use it again. */
      R_DecodePEMBlock
        (bytes, &binLen, (unsigned char *)vals[0], strlen (vals[0]));
      if (DERToPubKey (bytes, &recipientPublicKey) != 0) {
        errorMessage =
          "Could not decode Originator's public key in message header";
        break;
      }

      if (R_memcmp
          ((POINTER)&recipientPublicKey, (POINTER)&ripemInfo->publicKey,
           sizeof (recipientPublicKey)) == 0) {
        messageInfo->thisUser = TRUE;
        if (ripemInfo->debug > 1)
          fprintf(ripemInfo->debugStream,
                  "(This recipient is you via public key.)\n");
      }
      break;
    
    case RECIPIENT_ID_ASYMMETRIC_ENUM:
      if (nvals != 2) {
        errorMessage = "Bad Recipient-ID-Asymmetric value.";
        break;
      }

      /* Decode the issuer name.
       */
      binLen = DECRYPTED_CONTENT_LEN ((int)strlen (vals[0]));
      if ((bytes = (unsigned char *)malloc (binLen))
          == (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      /* Allocate the issuer name struct on the heap to save stack space. */
      if ((issuerName = (DistinguishedNameStruct *)malloc
           (sizeof (*issuerName))) == (DistinguishedNameStruct *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      /* CrackHeaderLine already strips leading and trailing blanks from
           values and null terminates. */
      /* Put output size in binLen, even though we don't use it again. */
      R_DecodePEMBlock
        (bytes, &binLen, (unsigned char *)vals[0], strlen (vals[0]));
      bytesPointer = bytes;
      if (DERToDistinguishedName (&bytesPointer, issuerName) != 0) {
        errorMessage =
          "Could not decode issuer name in Recipient-ID-Asymmetric";
        break;
      }

      /* Decode the serial number.
       */
      if ((serialNumberLen = HexToBin
           (vals[1], sizeof (serialNumber), serialNumber)) == 0) {
        errorMessage =
          "Could not decode serial number in Recipient-ID-Asymmetric";
        break;
      }

      /* Compute the alias and check if it is in the ripemInfo.
       */
      ComputeIssuerSerialAlias
        (alias, issuerName, serialNumber, (unsigned int)serialNumberLen);
      if (IsIssuerSerialAlias (ripemInfo, alias)) {
        messageInfo->thisUser = TRUE;
        if (ripemInfo->debug>1)
          fprintf(ripemInfo->debugStream,
                  "(This recipient is you via Recipient-ID-Asymmetric.)\n");
      }
      break;
    
    case DEK_ENUM:
      /* Get the message encryption type & if it
       * involves Cipher Block Chaining, also
       * get the Initialization Vector.
       */
      if(tok_vals[0] != DEK_ALG_DES_CBC_ID_ENUM &&
         tok_vals[0] != DEK_ALG_TDES_CBC_ID_ENUM) {
        sprintf(ripemInfo->errMsgTxt,"Can't process encryption type \"%s\".",
                vals[0]);
        errorMessage = ripemInfo->errMsgTxt;
        break;
      }
      if (tok_vals[0] == DEK_ALG_DES_CBC_ID_ENUM)
        messageInfo->ea = EA_DES_CBC;
      else
        messageInfo->ea = EA_DES_EDE2_CBC;

      /* An 8 byte IV is 16 hex characters */
      if(nvals<2 || strlen(vals[1])!=16) {
        errorMessage = "Invalid initialization vector.";
        break;
      }
      HexToBin (vals[1], 8, messageInfo->iv);
      break;
    
    case SENDER_ENUM:
      if(nvals != 1) {
        errorMessage = "Bad Originator-Name value.";
        break;
      }
      mylen = strlen(vals[0])+1;
      messageInfo->orig_name = malloc(mylen);
      if(!messageInfo->orig_name) {
        errorMessage = ERR_MALLOC;
        break;
      }
      strcpy (messageInfo->orig_name, vals[0]);
      if(ripemInfo->debug>1) {
        fprintf(ripemInfo->debugStream,"Originator-Name = %s [%d chars] %s\n",
                vals[0],mylen-1,messageInfo->orig_name);
      }
      
      break;
    
    case SENDER_PUB_KEY_ENUM:
      if(nvals != 1) {
        errorMessage = "Bad Originator-Key-Asymmetric value.";
        break;
      }
      
      binLen = DECRYPTED_CONTENT_LEN((int)strlen(vals[0]));
      if ((bytes = (unsigned char *)malloc(binLen))
          == (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }
      /* CrackHeaderLine already strips leading and trailing blanks from
           values and null terminates. */
      R_DecodePEMBlock
        (bytes, &binLen, (unsigned char *)vals[0], strlen (vals[0]));
      if(DERToPubKey(bytes,&(messageInfo->orig_pub_key)) != 0) {
        errorMessage =
          "Could not decode Originator's public key in message header";
        break;
      }
      messageInfo->got_orig_pub_key = TRUE;

      break;
    
    case ORIGINATOR_CERT_ENUM:
    case ISSUER_CERT_ENUM:
      if(nvals != 1) {
        errorMessage =
          "Bad Originator-Certificate or Issuer-Certificate value.";
        break;
      }

      /* Decode the certificate and add the DER to the list.
       */
      binLen = DECRYPTED_CONTENT_LEN ((int)strlen (vals[0]));
      if ((bytes = (unsigned char *)malloc (binLen))
          == (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }         
      /* CrackHeaderLine already strips leading and trailing blanks from
           values and null terminates. */
      R_DecodePEMBlock
        (bytes, &derLen, (unsigned char *)vals[0], strlen (vals[0]));

      /* Try to insert the certificate into the database. */
      if ((errorMessage = InsertUniqueCert
           (bytes, ripemInfo, ripemDatabase)) != (char *)NULL)
        break;
      
      if (messageInfo->proc_type != PROC_TYPE_CRL_ID_ENUM) {
        /* This is a normal message with a sender.  We have already inserted
           this cert into the database.  If this is the originator cert field,
           put it in the messageInfo, otherwise there is no reason to save it.
         */
        if (tok_field == ORIGINATOR_CERT_ENUM) {
          /* Free any existing originatorCert, which shouldn't be there. */
          free (messageInfo->originatorCert);

          messageInfo->originatorCert = bytes;

          /* The bytes were adopted into the messageInfo, so set to NULL
               so they won't be freed below. */
          bytes = (unsigned char *)NULL;
        }
      }

      break;
    
    case CRL_ENUM:
      if(nvals != 1) {
        errorMessage = "Bad CRL field value.";
        break;
      }

      /* Decode the CRL.
       */
      binLen = DECRYPTED_CONTENT_LEN ((int)strlen (vals[0]));
      if ((bytes = (unsigned char *)malloc (binLen))
          == (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }         
      /* CrackHeaderLine already strips leading and trailing blanks from
           values and null terminates. */
      R_DecodePEMBlock
        (bytes, &derLen, (unsigned char *)vals[0], strlen (vals[0]));

      /* If there is a CRL waiting in the messageInfo, then we
           try to insert it now.  (The certificates needed to validate it
           should have been read from the message by now.)
           We will save the CRL from the message to insert later.
           This has two advantages.  First, we only keep a minimum of CRLs
           in memory at a time which is good because they can be
           large.  And second, since the CRL message format puts the CRL
           *before* the certificates which are needed to validate it, we
           cannot insert the CRL until we have inserted the certificates into
           the database, which is accomplished by saving the CRL until later.
       */
      if (messageInfo->crlToInsert != (unsigned char *)NULL) {
        if ((errorMessage = VerifyAndInsertCRL
             (messageInfo->crlToInsert, ripemInfo, ripemDatabase))
            != (char *)NULL)
          break;
        free (messageInfo->crlToInsert);
        messageInfo->crlToInsert = (unsigned char *)NULL;
      }

      /* Now save the CRL for later. */
      messageInfo->crlToInsert = bytes;

      /* The bytes were adopted into the list, so set to NULL
           so they won't be freed below. */
      bytes = (unsigned char *)NULL;

      break;
    
    case MESSAGE_KEY_ENUM:
      /* Get the algorithm used to encrypt the message
       * key, and get the encrypted message key.
       */
      if(messageInfo->thisUser) {
        messageInfo->thisUser = FALSE;
        if (tok_vals[0] != ENCRYPTION_ALG_RSA_ID_ENUM) {
          sprintf(ripemInfo->errMsgTxt,"Unrecognized encryption type: %s",
                  vals[0]);
          errorMessage = ripemInfo->errMsgTxt;
          break;
        }
        messageInfo->msg_key_len = strlen(vals[1]);
        messageInfo->msg_key =
          (unsigned char *)malloc(messageInfo->msg_key_len+1);
        if(!messageInfo->msg_key) {
          errorMessage = ERR_MALLOC;
          break;
        }
        strcpy((char *)(messageInfo->msg_key),vals[1]);
      }

      break;
    
    case MIC_INFO_ENUM:
      if(tok_vals[0]==MIC_MD2_ID_ENUM) {
        messageInfo->da = DA_MD2;
      } else if(tok_vals[0]==MIC_MD5_ID_ENUM) {
        messageInfo->da = DA_MD5;
      } else if(tok_vals[0]==MIC_SHA1_ID_ENUM) {
        messageInfo->da = DA_SHA1;
      } else {
        errorMessage = "Unrecognized MIC algorithm.";
        break;
      }

      if (tok_vals[1] != ENCRYPTION_ALG_RSA_ID_ENUM) {
        errorMessage = "Unrecognized MIC encryption algorithm.";
      }
      if(nvals != 3) {
        errorMessage = "Missing encrypted MIC.";
        break;
      }
      messageInfo->mic_len = strlen(vals[2]);
      messageInfo->mic = (unsigned char *)malloc(messageInfo->mic_len+1);
      if(!messageInfo->mic) {
        errorMessage = ERR_MALLOC;
        break;
      }
      strcpy((char *)messageInfo->mic,vals[2]);

      break;

    default:
      sprintf (ripemInfo->errMsgTxt,
               "Illegal field in header: \"%s\" - Remove to process message",
               fieldName);
      errorMessage = ripemInfo->errMsgTxt;
      break;
    }
  } while (0);

  free (bytes);
  free (issuerName);
  FreeList(&val_list);
  return (errorMessage);
}

/* Break a header line into its constituent components.
   The line is considered to consist of a field name,
     optionally followed by comma-separated values.
 
   Entry:  line is a line from the message header.
           maxFieldNameSize is the size of the fieldName buffer.
 
   Exit:   fieldName has the field name, starting in the first column.
           valList     contains pointers to cracked-off comma-separated
                       values.  Leading and trailing spaces have
                       been trimmed.
           Returns the number of values cracked.
 */
static char *CrackHeaderLine (line, fieldName, maxFieldNameSize, valList)
char *line;
char *fieldName;
unsigned int maxFieldNameSize;
TypList *valList;
{
  unsigned int len;
  register char *cptr = line;
  char c;

  for (len = 0;
       *cptr && !WhiteSpace (*cptr) && (len + 1) < maxFieldNameSize;
       ++len) {
    c = *(cptr++);
    *(fieldName++) = c;

    if (c == ':')
      /* Stop after colon, even if there is no following white space */
      break;
  }
  *fieldName = '\0';
  
  return (CrackLine (cptr, valList));
}

/*--- function CrackLine --------------------------------------------------
 *
 *  Crack a comma-delimited line of text into individual elements.
 *
 *  Entry:  line is a line delimited by comma or \n.
 *          valList must already by initialized with InitList.  This
 *            calls FreeList on valList first to make sure it's empty.
 *
 *  Exit:   valList     is a list of the cracked-off comma-separated
 *                      values.  Leading and trailing spaces have
 *                      been trimmed.
 *          Returns NULL, or an error message.
 */
char *CrackLine (line, valList)
char *line;
TypList *valList;
{
  unsigned int len;
  char *linePointer = line, *valuePointer, *errorMessage = (char *)NULL,
    *newValue = (char *)NULL;
  
  /* For error, break to end of do while (0) block. */
  do {
    FreeList (valList);

    while (*linePointer) {
      while (*linePointer && WhiteSpace (*(linePointer)))
        linePointer++;
      if (*linePointer) {
        /* We have found a value.  Point valuePointer at the start and
             find the end. */
        valuePointer = linePointer;
        for (len = 0;
             *linePointer && *linePointer != ',' && *linePointer != '\n';
             len++)
          linePointer++;

        /* Trim trailing blanks. */
        while (len > 0 && valuePointer[len - 1] == ' ')
          len--;

        /* Allocate a buffer, copy the string to it with null terminator
             and add to the list.
         */
        if ((newValue = (char *)malloc (len + 1)) == (char *)NULL) {
          errorMessage = ERR_MALLOC;
          break;
        }
        R_memcpy ((POINTER)newValue, (POINTER)valuePointer, len);
        newValue[len] = '\0';
        if ((errorMessage = AddToList (NULL, newValue, len + 1, valList))
            != (char *)NULL)
          break;
        /* AddToList succeeded, so we don't want to free newValue */
        newValue = (char *)NULL;

        /* If we're not already at a comma, skip to the comma or EOL */
        while (*linePointer && *linePointer != ',' && *linePointer != '\n')
          linePointer++;
        if (*linePointer == ',')
          linePointer++;
      }
    }
  } while (0);

  /* Free newValue if it wasn't successfully added to the list */
  free (newValue);
  return (errorMessage);
}

/*--- function TokenizeHeaderLine ----------------------------------
 *
 */
static void
TokenizeHeaderLine(fieldName,vals,nvals,tok_field,tok_vals)
char *fieldName;
char **vals;
int nvals;
enum enum_fields *tok_field;
enum enum_ids    tok_vals[];
{
  int j, ival;

  for(j=0; FieldNames[j] && !R_match(FieldNames[j],fieldName);j++);

  *tok_field = (enum enum_fields) j;

  for(ival=0; ival<nvals; ival++) {
    for(j=0; IDNames[j] && !R_match(IDNames[j],vals[ival]); j++);
    tok_vals[ival] = (enum enum_ids)j;
  }
}

/*--- function NameInList ----------------------------------------------
 *
 *  Determine whether a given username matches any of the aliases
 *  for a email address.
 *
 *  Entry:  name      the name we're checking, zero-terminated.
 *        userList    List of aliases to my username.
 *
 *   Exit:  Returns TRUE if a match found, else FALSE.
 */
static BOOL
NameInList(name,userList)
char *name;
TypList *userList;
{
  TypListEntry *entry;
  BOOL found=FALSE;
  
  for(entry=userList->firstptr; entry && !found; entry=entry->nextptr) {
    found = R_match(name,entry->dataptr);
  }
  return found;
}

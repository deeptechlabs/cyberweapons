/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef SVRV32
#include <sys/types.h>
#endif /* SVRV32 */
#include "global.h"
#include "rsaref.h"
#include "ripem.h"

#ifdef MSDOS
#include <io.h>
#include <time.h>
#ifndef __TURBOC__
#include <malloc.h>
#else
#include <alloc.h>
#endif
#endif

#ifndef IBMRT
#include <stdlib.h>
#endif
#include <errno.h>

#if !defined (__convexc__) && !defined(apollo) && !defined(__TURBOC__)
#include <memory.h>
#endif

#include <string.h>

#include "headers.h"
#include "keyfield.h"
#include "strutilp.h"
#include "keyderpr.h"
#include "derkeypr.h"
#include "keymanpr.h"
#include "bemparse.h"
#include "hexbinpr.h"
#include "bfstream.h"
#include "certder.h"
#include "certutil.h"
#include "crackhpr.h"
#include "rdwrmsgp.h"
#include "p.h"

#ifdef UNIX
#ifdef __MACH__
#include <libc.h>
#endif
#include <pwd.h>
#endif

#ifdef MACTC
#include <stdlib.h>
#include <console.h>
#include <time.h>
#endif

#define IV_SIZE 8

typedef struct {
  RIPEMEncipherFrame ripemEncipherFrame;                      /* "base class */
  BufferStream outStream;     /* This holds the value returned to the caller */
  enum enhance_mode enhanceMode;
  int messageFormat;
  unsigned char iv[IV_SIZE];
  /* We must save the encrypted keys throughout RIPEMEncipherDigestUpdate */
  unsigned int recipientKeyCount;
  RecipientKeyInfo *recipientKeys;   /* data must remain valid through calls */
  int encryptionAlgorithm;
  int digestAlgorithm;
  unsigned char *encryptedKeysBuffer;
  unsigned int *encryptedKeyLens;
  TypList issuerNames;
  R_ENVELOPE_CTX sealContext;
  R_SIGNATURE_CTX signatureContext;
  BOOL wroteHeader;
  BOOL lastWasNewline;                     /* Used in MIC-CLEAR dashstuffing */
  BufferStream buffer;                 /* Used to accumulate lines to encode */
} RIPEMEncipherPEMFrame;

typedef struct {
  RIPEMDecipherFrame ripemDecipherFrame;                      /* "base class */
  BufferStream outStream;     /* This holds the value returned to the caller */
  TypMsgInfo messageInfo;
  BufferStream lineIn;            /* Used to accumulate a line during Update */
  BOOL doingHeader;
  unsigned char decryptedLine[1000];
  unsigned char signature[MAX_SIGNATURE_LEN];
  unsigned int signatureLen;
  R_ENVELOPE_CTX envelopeContext;
  R_SIGNATURE_CTX signatureContext;
  R_RSA_PUBLIC_KEY senderKey;                /* used to execute final verify */
  BOOL foundEndBoundary;
  TypList headerList;                         /* for saving the email header */
  TypList certChain;                              /* Local copy of certChain */
  ChainStatusInfo chainStatus;
  BOOL prependHeaders;                    /* Saved copy of parameter to Init */
} RIPEMDecipherPEMFrame;

typedef struct {
  RIPEM_CRLsFrame ripemCRLsFrame;                             /* "base class */
  BufferStream outStream;     /* This holds the value returned to the caller */
} RIPEM_CRLsPEMFrame;

void RIPEMEncipherPEMFrameConstructor P((RIPEMEncipherPEMFrame *));
void RIPEMEncipherPEMFrameDestructor P((RIPEMEncipherPEMFrame *));
void RIPEMDecipherPEMFrameConstructor P((RIPEMDecipherPEMFrame *));
void RIPEMDecipherPEMFrameDestructor P((RIPEMDecipherPEMFrame *));
void RIPEM_CRLsPEMFrameConstructor P((RIPEM_CRLsPEMFrame *));
void RIPEM_CRLsPEMFrameDestructor P((RIPEM_CRLsPEMFrame *));
static char *WriteHeader
  P((RIPEMInfo *, unsigned char *, unsigned int, RIPEMDatabase *));
static char *WriteKeyInfo P((unsigned char *, unsigned int, BufferStream *));
static char *WriteRecipientIDAsymmetric
  P((DistinguishedNameStruct *, unsigned char *, unsigned int,
     BufferStream *));
static char *ReadEnhancedTextLine
  P((RIPEMDecipherPEMFrame *, BufferStream *, char *));
static char *ProcessHeader P((RIPEMInfo *, BufferStream *, RIPEMDatabase *));
static char *SignFinalOutputHeader P((RIPEMInfo *, RIPEMDatabase *));
static char *WriteMessage
  P((unsigned char *, unsigned int, BOOL, BufferStream *));
static char *WriteOriginatorAndIssuerCerts
  P((RIPEMInfo *, BufferStream *, int));
#ifndef RIPEMSIG
static int RIPEMOpenInit
  P ((RIPEMInfo *, R_ENVELOPE_CTX *, unsigned char *, unsigned int *));
static int MyDecryptPEMUpdateFinal PROTO_LIST
  ((R_ENVELOPE_CTX *, unsigned char *, unsigned int *, unsigned char *,
    unsigned int));
#endif

/* Initialize for preparing a PEM message according to enhanceMode.
   The calling routine must already have called RIPEMLoginUser.
   If enhanceMode is MODE_ENCRYPTED, then encryptionAlgorithm is
     a value recognized by RSAREF, like EA_DES_CBC.  Also, recipientKeys
     is an array of recipientKeyCount RecipientKeyInfo structs.  These
     give the public keys and usernames of the recipients.  The username
     is used for backward compatibility with RIPEM 1.1 and for looking
     up the user's issuer name and serial number for MESSAGE_FORMAT_PEM
     compatibility. The randomStruct in ripemInfo must already be initialized.
     The data pointed to by recipientKeys must remain valid until the first
     call to RIPEMEncipherUpdate.
   messageFormat must be MESSAGE_FORMAT_RIPEM1 or MESSAGE_FORMAT_PEM to
     choose which format the message is compatible with.
     MESSAGE_FORMAT_RIPEM1 is compatible with RIPEM 1.1 and 1.2.  It has
     a Proc-Type version of 2001 and includes the Originator-Name field and
     uses Recipient-Key-Asymmetric (containing the public key) for the
     recipients of encrypted messages. MESSAGE_FORMAT_PEM is for comatibility
     with the RFC 1421 standards suite.  It has a Proc-Type version of 4 and
     omits RIPEM-specific fields such as Originator-Name and
     uses only Recipient-ID-Asymmetric (containing issuer name and serial
     number) for the recipients of encrypted messages.
   After this, call RIPEMEncipherDigestUpdate to digest the text
     by parts, RIPEMEncipherUpdate to enhance the text by parts,
     and call RIPEMEncipherFinal to finish.
   Return NULL for success or error string.
 */
char *RIPEMEncipherInit
  (ripemInfo, enhanceMode, messageFormat, digestAlgorithm, encryptionAlgorithm,
   recipientKeys, recipientKeyCount)
RIPEMInfo *ripemInfo;
enum enhance_mode enhanceMode;
int messageFormat;
int digestAlgorithm;
int encryptionAlgorithm;
RecipientKeyInfo *recipientKeys;
unsigned int recipientKeyCount;
{
  RIPEMEncipherPEMFrame *frame;
  int status;
#ifndef RIPEMSIG
  char *errorMessage;
#endif
  
#ifdef RIPEMSIG
UNUSED_ARG (encryptionAlgorithm)
UNUSED_ARG (recipientKeys)
UNUSED_ARG (recipientKeyCount)
#endif
  
  if (enhanceMode != MODE_ENCRYPTED && enhanceMode != MODE_MIC_ONLY &&
      enhanceMode != MODE_MIC_CLEAR)
    return ("Invalid encipher mode.");
  if (messageFormat != MESSAGE_FORMAT_RIPEM1 &&
      messageFormat != MESSAGE_FORMAT_PEM)
    return ("Invalid message format.");

  /* Make sure any old frame is deleted and make a new one.
   */
  if (ripemInfo->z.encipherFrame != (RIPEMEncipherFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.encipherFrame->Destructor) (ripemInfo->z.encipherFrame);
    free (ripemInfo->z.encipherFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEMEncipherPEMFrame */
  if ((ripemInfo->z.encipherFrame = (RIPEMEncipherFrame *)malloc
       (sizeof (*frame))) == (RIPEMEncipherFrame *)NULL)
    return (ERR_MALLOC);
  RIPEMEncipherPEMFrameConstructor
    ((RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame);

  frame = (RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame;
  frame->enhanceMode = enhanceMode;
  frame->messageFormat = messageFormat;
  frame->digestAlgorithm = digestAlgorithm;

  if (enhanceMode == MODE_ENCRYPTED) {
#ifdef RIPEMSIG
    return ("RIPEM/SIG cannot prepare encrypted messages. You may prepare signed messages.");
#else
    if (recipientKeyCount == 0)
      return ("You must specify at least one recipient");

    frame->recipientKeyCount = recipientKeyCount;
    frame->recipientKeys = recipientKeys;
    frame->encryptionAlgorithm = encryptionAlgorithm;
    
    /* Allocate arrays for the encrypted key pointers.
     */
    if ((frame->encryptedKeysBuffer = (unsigned char *)malloc
         (recipientKeyCount * MAX_ENCRYPTED_KEY_LEN)) ==
        (unsigned char *)NULL)
      return (ERR_MALLOC);
    if ((frame->encryptedKeyLens = (unsigned int *)malloc
         (recipientKeyCount * sizeof (*frame->encryptedKeyLens))) ==
        (unsigned int *)NULL)
      return (ERR_MALLOC);

    /* Create all of the recipient key info blocks and generate the iv.
       We can't output now because the signature comes before the
         encrypted keys in the header.
     */
    if ((errorMessage = RIPEMSealInit
         (ripemInfo, &frame->sealContext, frame->iv,
          frame->encryptedKeysBuffer, frame->encryptedKeyLens, recipientKeys,
          recipientKeyCount, encryptionAlgorithm)) != (char *)NULL)
      return (errorMessage);
#endif
  }
  
  /* Initialize signature */
  if ((status = R_SignInit (&frame->signatureContext, digestAlgorithm)) != 0)
    return (FormatRSAError (status));
  
  return ((char *)NULL);
}

/* This must be called because the signature comes before the enhanced text
     so we must digest the text first before we can output the signature
     and enhanced the text.  Call this zero or more times to supply
     the input text.  Then call RIPEMEncipherUpdate to actually enhance
     and output the text.  Between the last call to RIPEMEncipherDigestUpdate
     and the first call to RIPEMEncipherUpdate, you must rewind the input.
   The text to enhance is in partIn with length partInLen.  Textual lines must
     be delimited by the '\n' character (not <CR><LF>).  This can be
     done for example by reading from a file with fgets or fread in text mode.
     This routine will convert to <CR><LF> internally as needed for
     digesting.  Make sure there is a \n at the end of the final line.
   Return NULL for success or error string.
 */
char *RIPEMEncipherDigestUpdate (ripemInfo, partIn, partInLen)
RIPEMInfo *ripemInfo;
unsigned char *partIn;
unsigned int partInLen;
{
  RIPEMEncipherPEMFrame *frame =
    (RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame;
  unsigned int i, status;

  if (frame == (RIPEMEncipherPEMFrame *)NULL)
    return ("Encipher not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPEMFrameDestructor)
    return ("Encipher frame was not initialized by RIPEMEncipherInit");

  /* We must digest the text, substituting <CR><LF> for all '\n'.
   */
  while (1) {
    /* Position i at the first \n or at the end of partIn and then digest.
     */
    for (i = 0; i < partInLen && partIn[i] != '\n'; ++i);
    if ((status = R_SignUpdate (&frame->signatureContext, partIn, i)) != 0)
      return (FormatRSAError (status));

    if (i == partInLen)
      /* We have digested up the end of partIn, so return to await another
           call to DigestUpdate. */
      return ((char *)NULL);

    /* i is positioned on a '\n', so digest a <CR><LF>.
     */
    if ((status = R_SignUpdate
         (&frame->signatureContext, (unsigned char *)"\015\012", 2)) != 0)
      return (FormatRSAError (status));

    /* Move partIn past the \n.
     */
    ++i;
    partInLen -= i;
    partIn += i;
  }
}

/* (Before this is called for the first time, the caller should have made
     calls to RIPEMEncipherDigestUpdate and then rewound the input.)
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   The output is textual lines delimited by the character '\n'.
     The caller must convert these to the local line delimiter, such as
     writing to a file with fwrite in text mode.
   The text to enhance is in partIn with length partInLen.  Textual lines must
     be delimited by the '\n' character (not <CR><LF>).  This can be
     done for example by reading from a file with fgets or fread in text mode.
     This routine will convert to <CR><LF> internally as needed.
     Make sure there is a \n at the end of the final line.
   ripemDatabase is used for selecting certificates to find issuer names
     and serial numbers of recipients for MESSAGE_FORMAT_PEM.
   Return NULL for success or error string.
 */
char *RIPEMEncipherUpdate
  (ripemInfo, partOut, partOutLen, partIn, partInLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
unsigned char *partIn;
unsigned int partInLen;
RIPEMDatabase *ripemDatabase;
{
  RIPEMEncipherPEMFrame *frame =
    (RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame;
  char *errorMessage;
  unsigned int i, remainingBytes;
#ifndef RIPEMSIG
  int status;
  unsigned int localPartOutLen;
#endif

  if (frame == (RIPEMEncipherPEMFrame *)NULL)
    return ("Encipher not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPEMFrameDestructor)
    return ("Encipher frame was not initialized by RIPEMEncipherInit");

  /* Get ready to write to the output. */
  BufferStreamRewind (&frame->outStream);

  if (!frame->wroteHeader) {
    /* This is the first call to Update, so write out the header. */

    if ((errorMessage = SignFinalOutputHeader (ripemInfo, ripemDatabase))
        != (char *)NULL)
      return (errorMessage);
    frame->wroteHeader = TRUE;
  }

  if (ripemInfo->debug > 1) {
#define DEBUGCHARS 500
    unsigned int maxbytes =
      partInLen < DEBUGCHARS ? partInLen : DEBUGCHARS, idx=0;
    unsigned char dch;

    fprintf (ripemInfo->debugStream,"%d bytes in; first %d bytes are:\n",
             partInLen, maxbytes);
    while (idx < maxbytes) {
      dch = partIn[idx++];
      if (isprint((char)dch))
        putc ((char)dch,ripemInfo->debugStream);
      else
        fprintf (ripemInfo->debugStream, "\\x%2.2x", dch);
    }
    putc ('\n', ripemInfo->debugStream);
  }

  if (frame->enhanceMode == MODE_ENCRYPTED ||
      frame->enhanceMode == MODE_MIC_ONLY) {
    /* First convert \n in the partIn to <CR><LF> by writing to
         the frame->buffer.
     */
    while (1) {
      /* Position i at the first \n or at the end of partIn and then
           copy bytes up to here into the buffer. */
      for (i = 0; i < partInLen && partIn[i] != '\n'; ++i);
      if ((errorMessage = BufferStreamWrite (partIn, i, &frame->buffer))
          != (char *)NULL)
        return (errorMessage);

      if (i == partInLen)
        /* We have copied up the end of partIn, so break. */
        break;

      /* i is positioned on a '\n', so copy a <CR><LF>.
       */
      if ((errorMessage = BufferStreamWrite
           ((unsigned char *)"\015\012", 2, &frame->buffer)) != (char *)NULL)
        return (errorMessage);

      /* Move partIn past the \n. */
      ++i;
      partInLen -= i;
      partIn += i;
    }

    /* Set i to as many multiples of ENCODE_CHUNKSIZE in buffer. */
    i = (frame->buffer.point / ENCODE_CHUNKSIZE) * ENCODE_CHUNKSIZE;

    if (i > 0) {
#ifndef RIPEMSIG
      if (frame->enhanceMode == MODE_ENCRYPTED) {
        /* Becuase i is a multiple of ENCODED_CHUNKSIZE which is
             a multiple of the DES block size (8), we can encrypt
             in place without any leftover.  localPartOutLen should equal
             the part in len.
         */
        if ((status = R_SealUpdate
             (&frame->sealContext, frame->buffer.buffer, &localPartOutLen,
              frame->buffer.buffer, i)) != 0)
          return (FormatRSAError (status));

        if (ripemInfo->debug > 1) {
          char hex_digest[36];

          fprintf
            (ripemInfo->debugStream, "EncContentLen=%u (not recoded)\n",
             localPartOutLen);
          MakeHexDigest (frame->buffer.buffer, localPartOutLen, hex_digest);
          fprintf
            (ripemInfo->debugStream, " MD5 of encrypted content = %s\n",
             hex_digest);
        }
      }
#endif
      /* Because i is a multiple of ENCODE_CHUNKSIZE, all lines will
           be written of the same length. */
      if ((errorMessage = BufferCodeAndWriteBytes
           (frame->buffer.buffer, i, "", &frame->outStream)) != (char *)NULL)
        return (errorMessage);

      /* Rewind and write the remaining bytes to the beginning of
           the buffer.  This will not overlap because the remaining bytes
           start >= ENCODE_CHUNKSIZE, but there are less than
           ENCODE_CHUNKSIZE remaining bytes.  Set remainingBytes before
           we rewind the point to 0. */
      remainingBytes = frame->buffer.point - i;
      BufferStreamRewind (&frame->buffer);
      if ((errorMessage = BufferStreamWrite
           (frame->buffer.buffer + i, remainingBytes, &frame->buffer))
          != (char *)NULL)
        return (errorMessage);
    }
  }
  else {
    /* MIC-CLEAR.  Copy the input to the output, changing "\n-"
         to "\n- -".  Note that we don't need to use the frame->buffer.
     */

    if (frame->lastWasNewline) {
      /* Special case: the character at the end of the previous partIn
           was a newline, so see if this partIn starts with a dash. */
      if (partInLen > 0 && partIn[0] == '-') {
        /* partIn starts with a dash and we have already output the
             newline, so output a "- -".
         */
        if ((errorMessage = BufferStreamWrite
             ((unsigned char *)"- -", 3, &frame->outStream)) != (char *)NULL)
          return (errorMessage);

        /* Move partIn past the dash. */
        --partInLen;
        ++partIn;
      }

      frame->lastWasNewline = FALSE;
    }

    while (1) {
      /* Position i at the first "\n-" or at the end of partIn and then
           copy bytes up to here to the output. */
      for (i = 0; i < partInLen; ++i) {
        if (partIn[i] == '\n' && (i + 1 < partInLen) &&
            partIn[i + 1] == '-')
          break;
      }
      if ((errorMessage = BufferStreamWrite (partIn, i, &frame->outStream))
          != (char *)NULL)
        return (errorMessage);

      if (i == partInLen) {
        /* We have copied up the end of partIn, so break.  Set the
             lastWasNewline flag so we can check new input for
             '-' at the beginning of line. */
        if (partInLen > 0 && partIn[partInLen - 1] == '\n')
          frame->lastWasNewline = TRUE;
        break;
      }

      /* i is positioned on a "\n-", so copy a "\n- -".
       */
      if ((errorMessage = BufferStreamWrite
           ((unsigned char *)"\n- -", 4, &frame->outStream)) != (char *)NULL)
        return (errorMessage);

      /* Move partIn past the "\n-". */
      i += 2;
      partInLen -= i;
      partIn += i;
    }
  }

  /* Set the output. */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Call this after all text has been fed to RIPEMEncipherUpdate.  This
     flushes the output and writes the end message boundary.  See
     RIPEMEncipherUpdate for a description of partOut and partOutLen.
   Note that if the message text is blank and RIPEMEncipherUpdate was
     never called, this will still output a header and empty message.
   ripemDatabase is used for selecting certificates to find issuer names
     and serial numbers of recipients for MESSAGE_FORMAT_PEM.
   Return NULL for success or error string.
 */
char *RIPEMEncipherFinal (ripemInfo, partOut, partOutLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
RIPEMDatabase *ripemDatabase;
{
  RIPEMEncipherPEMFrame *frame =
    (RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame;
  char *errorMessage;
#ifndef RIPEMSIG
  unsigned int updateLen, finalLen;
  unsigned char finalBuffer[8];
  int status;
#endif
  
  if (frame == (RIPEMEncipherPEMFrame *)NULL)
    return ("Encipher not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPEMFrameDestructor)
    return ("Encipher frame was not initialized by RIPEMEncipherInit");

  /* Get ready to write to the output. */
  BufferStreamRewind (&frame->outStream);

  if (!frame->wroteHeader) {
    /* This implies the text is zero length. */
    if ((errorMessage = SignFinalOutputHeader (ripemInfo, ripemDatabase))
        != (char *)NULL)
      return (errorMessage);
  }

#ifndef RIPEMSIG
  if (frame->enhanceMode == MODE_ENCRYPTED) {
    /* Encrypt update the buffer's remaining bytes in place.  For encrypt
         final, use a local buffer since it might write past the frame's
         buffer end.
     */
    if ((status = R_SealUpdate
         (&frame->sealContext, frame->buffer.buffer, &updateLen,
          frame->buffer.buffer, frame->buffer.point)) != 0)
      return (FormatRSAError (status));
    if ((status = R_SealFinal
         (&frame->sealContext, finalBuffer, &finalLen)) != 0)
      return (FormatRSAError (status));
    /* Now set the buffer's point to where update has written bytes to
         and write the result of seal final.
     */
    frame->buffer.point = updateLen;
    if ((errorMessage = BufferStreamWrite
         (finalBuffer, finalLen, &frame->buffer)) != (char *)NULL)
      return (errorMessage);

    /* Encode and write out.
     */
    if ((errorMessage = BufferCodeAndWriteBytes
         (frame->buffer.buffer, frame->buffer.point, "", &frame->outStream))
        != (char *)NULL)
      return (errorMessage);
  }
#endif
  if (frame->enhanceMode == MODE_MIC_ONLY) {
    /* Encode and write out any remaining bytes in the buffer.
     */
    if ((errorMessage = BufferCodeAndWriteBytes
         (frame->buffer.buffer, frame->buffer.point, "", &frame->outStream))
        != (char *)NULL)
      return (errorMessage);
  }
  /* For MIC-CLEAR, assume the last line ended with a \n and has been
       processed. */

  if ((errorMessage = BufferStreamPuts (HEADER_STRING_END, &frame->outStream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (&frame->outStream)) != (char *)NULL)
    return (errorMessage);

  /* Set the output. */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Initialize ripemInfo for deciphering a PEM message.
   If prependHeaders is TRUE, the email headers from the input will be written
     to the output before the deciphered text.
   After this, call RIPEMDecipherUpdate to supply the enhanced message
     by parts and call RIPEMDecipherFinal to finish and obtain the
     sender information.
   Return NULL for success or error string.
 */
char *RIPEMDecipherInit (ripemInfo, prependHeaders)
RIPEMInfo *ripemInfo;
BOOL prependHeaders;
{
  RIPEMDecipherPEMFrame *frame;

  /* Make sure any old frame is deleted and make a new one.
   */
  if (ripemInfo->z.decipherFrame != (RIPEMDecipherFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.decipherFrame->Destructor) (ripemInfo->z.decipherFrame);
    free (ripemInfo->z.decipherFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEMDecipherPEMFrame */
  if ((ripemInfo->z.decipherFrame = (RIPEMDecipherFrame *)malloc
       (sizeof (*frame))) == (RIPEMDecipherFrame *)NULL)
    return (ERR_MALLOC);
  RIPEMDecipherPEMFrameConstructor
    ((RIPEMDecipherPEMFrame *)ripemInfo->z.decipherFrame);

  frame = (RIPEMDecipherPEMFrame *)ripemInfo->z.decipherFrame;
  frame->prependHeaders = prependHeaders;

  return ((char *)NULL);
}

/* Decipher the message in partIn, which contains the enhanced
     message with lines delimited by '\n' (not <CR><LF>).  partIn
     may contain parts of lines or multiple lines.
  This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   This converts any <CR><LF> line delimiters in the enhanced message
     back to '\n' in the output.
   Return NULL for success or error string.
 */
char *RIPEMDecipherUpdate
  (ripemInfo, partOut, partOutLen, partIn, partInLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
unsigned char *partIn;
unsigned int partInLen;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage = (char *)NULL;
  RIPEMDecipherPEMFrame *frame =
    (RIPEMDecipherPEMFrame *)ripemInfo->z.decipherFrame;
  int status;
  unsigned int i;

  if (frame == (RIPEMDecipherPEMFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPEMFrameDestructor)
    return ("Decipher frame was not initialized by RIPEMDecipherInit");

  /* Get ready to write to the output. */
  BufferStreamRewind (&frame->outStream);

  while (1) {
    if (!frame->doingHeader && frame->foundEndBoundary)
      /* partIn only contains stuff after the end boundary, so
           ignore. partOutLen will be set to zero below */
      break;

    /* Position i at the first \n or at the end of partIn and then
         copy bytes up to here into lineIn. */
    for (i = 0; i < partInLen && partIn[i] != '\n'; ++i);
    if ((errorMessage = BufferStreamWrite (partIn, i, &frame->lineIn))
        != (char *)NULL)
      return (errorMessage);

    if (i == partInLen)
      /* We have copied up the end of partIn, so break to set the
           partOutLen and return to await another call to Update
           to give the rest of the line */
      break;

    /* i is positioned on a '\n', so null terminate lineIn and process.
     */
    if ((errorMessage = BufferStreamPutc (0, &frame->lineIn))
        != (char *)NULL)
      return (errorMessage);
    if (frame->doingHeader) {
      if ((errorMessage = ProcessHeaderLine
           (ripemInfo, &frame->messageInfo, &frame->doingHeader,
            (char *)frame->lineIn.buffer, frame->prependHeaders,
            &frame->headerList, ripemDatabase)) != (char *)NULL)
        return (errorMessage);

      if (!frame->doingHeader) {
        /* We have finished reading the header, so process it.
           The doingHeader flag could have been set false by an end
             PEM boundary.  Assume this only happens for CRL messages since
             process type MIC-ONLY, etc. will assume the header ended with
             a blank line and will continue to try to read the message text.
         */
        if ((errorMessage = ProcessHeader
             (ripemInfo, &frame->outStream, ripemDatabase)) != (char *)NULL)
          return (errorMessage);
          
        if (frame->foundEndBoundary)
          /* ProcessHeader set this flag which means there is nothing
               more to process. */
          break;

        /* Initialize the signature context. */
        if ((status = R_VerifyInit
             (&frame->signatureContext, frame->messageInfo.da)) != 0)
            return (FormatRSAError (status));
          
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
                   "Before call to ReadEnhancedTextLine, Username=%s\n",
                   GetDNSmartNameValue (&ripemInfo->userDN));
      }
    }
    else {
      /* We have already processed the header.
         Now process the text and write out the result.
         If already found the end PEM boundary, this will do nothing.
       */
      if ((errorMessage = ReadEnhancedTextLine
           (frame, &frame->outStream, (char *)frame->lineIn.buffer))
          != (char *)NULL)
        return (errorMessage);
    }

    /* Move partIn past the \n and rewind the lineIn to start a new line.
     */
    ++i;
    partInLen -= i;
    partIn += i;
    BufferStreamRewind (&frame->lineIn);
  }

  /* Set the output. */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Call this after the entire enhanced message has been supplied to
     RIPEMDecipherUpdate.
   Return the sender's certChain and chainStatus. The calling routine must
     InitList certChain.  chainStatus is pointer to a ChainStatusInfo struct.
   If chainStatus->overall is 0, this could not find a valid public key for
     the sender and enhanceMode is undefined. In this case, if the message
     contained a self-signed certificate, the certChain contains one entry
     which is the self-signed cert.  The calling routine may decode it and
     present the self-signed cert digest, and use ValidateAndWriteCert to
     validate the user.
   If chainStatus->overall is CERT_UNVALIDATED, then this could not find a
     certificate for the sender, but could find an unvalidated public key.
     In this case, certChain contains one entry which is the sender's
     username.  This is provided only for compatibility with RIPEM 1.1.
   For other values of chainStatus->overall, certChain and chainStatus
     contains values as described in SelectCertChain.  Note: the sender
     name is the subject of the cert at the "bottom" of the chain.
   Return the enhanced mode, such as MODE_ENCRYPTED, in enhanceMode.  If the
     message is a CRL message, enhanceMode is set to MODE_CRL, certChain is
     unmodified since there are no senders, and chainStatus->overall
     is set to zero.
   Return NULL for success or error string.  If this returns
     ERR_NO_PEM_HEADER_BEGIN, then couldn't find the begin privacy enhanced
     message boundary.
 */
char *RIPEMDecipherFinal (ripemInfo, certChain, chainStatus, enhanceMode)
RIPEMInfo *ripemInfo;
TypList *certChain;
ChainStatusInfo *chainStatus;
enum enhance_mode *enhanceMode;
{
  RIPEMDecipherPEMFrame *frame =
    (RIPEMDecipherPEMFrame *)ripemInfo->z.decipherFrame;
  int status;

  if (frame == (RIPEMDecipherPEMFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPEMFrameDestructor)
    return ("Decipher frame was not initialized by RIPEMDecipherInit");

  /* The caller has reached an end of stream. Check premature end
       of stream conditions.
   */
  if (frame->doingHeader) {
    /* This really shouldn't happen since we should
         normally read a blank line after the header.
     */
    if (frame->messageInfo.foundBeginBoundary)
      return ("Unexpected end of stream while reading header");
    else
      return (ERR_NO_PEM_HEADER_BEGIN);
  }
  else {
    /* It is an error if we haven't read the end boundary. */
    if (!frame->foundEndBoundary)
      return ("Could not find END PRIVACY-ENHANCED MESSAGE boundary");
  }

  if (frame->messageInfo.proc_type == PROC_TYPE_CRL_ID_ENUM) {
    /* CRL message */
    *enhanceMode = MODE_CRL;
    chainStatus->overall = 0;
    return ((char *)NULL);
  }

  /* If the chain status is zero, we couldn't find a public key.
       Perhaps there is a self-signed cert to validate, so copying the
       certChain later is important, but don't try to validate the message
       signature. */
  if (frame->chainStatus.overall != 0) {
    /* We have digested the text, so check the signature.
     */
    if ((status = R_VerifyFinal
         (&frame->signatureContext, frame->signature, frame->signatureLen,
          &frame->senderKey)) != 0)
      return (FormatRSAError (status));

    /* Convert the enum_ids to an enhance_mode value.
     */
    if (frame->messageInfo.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM)
      *enhanceMode = MODE_ENCRYPTED;
    else if (frame->messageInfo.proc_type == PROC_TYPE_MIC_ONLY_ID_ENUM)
      *enhanceMode = MODE_MIC_ONLY;
    else if (frame->messageInfo.proc_type == PROC_TYPE_MIC_CLEAR_ID_ENUM)
      *enhanceMode = MODE_MIC_CLEAR;
  }
  
  /* Now return the sender's info to the caller.  Copy the chain's TypList
       which will transfer all the pointers to the caller.  Then re-initialize
       the frame's TypList so that the destructor won't try to free the memory.
   */
  *certChain = frame->certChain;
  InitList (&frame->certChain);
  /* This copies the entire ChainStatusInfo. */
  *chainStatus = frame->chainStatus;

  return ((char *)NULL);
}

/* Initialize a CRL retrieval request message.
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   Returns NULL for success, otherwise error string.
 */
char *RIPEMRequestCRLsInit (ripemInfo, partOut, partOutLen)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
{
  RIPEM_CRLsPEMFrame *frame;
  BufferStream *stream;
  char *errorMessage;
  
  /* Make sure any old frame is deleted and make a new one.
   */
  if (ripemInfo->z.crlsFrame != (RIPEM_CRLsFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.crlsFrame->Destructor) (ripemInfo->z.crlsFrame);
    free (ripemInfo->z.crlsFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEM_CRLsPEMFrame */
  if ((ripemInfo->z.crlsFrame = (RIPEM_CRLsFrame *)malloc
       (sizeof (*frame))) == (RIPEM_CRLsFrame *)NULL)
    return (ERR_MALLOC);
  RIPEM_CRLsPEMFrameConstructor
    ((RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame);

  /* Get stream for quick access. */
  frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  /* Put out header indicating encapsulated message follows. */
  if ((errorMessage = BufferStreamPuts (HEADER_STRING_BEGIN, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
    return (errorMessage);

  /* Put out field indicating processing type. */
  if ((errorMessage = BufferStreamPuts (PROC_TYPE_FIELD, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPuts (PROC_TYPE_PEM_ID, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamPuts
       (IDNames[PROC_TYPE_CRL_REQUEST_ID_ENUM], stream)) != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
    return (errorMessage);

  /* Set the output. */
  *partOut = stream->buffer;
  *partOutLen = stream->point;

  return ((char *)NULL);
}

/* Update a CRL retrieval request message by outputting the given name
     as an "Issuer:" field in the request.
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   Returns NULL for success, otherwise error string.
 */
char *RIPEMRequestCRLsUpdate (ripemInfo, partOut, partOutLen, name)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
DistinguishedNameStruct *name;
{
  RIPEM_CRLsPEMFrame *frame;
  BufferStream *stream;
  char *errorMessage;
  unsigned char *der = (unsigned char *)NULL, *derPointer;
  
  /* For error, break to end of do while (0) block. */
  do {
    frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
    if (frame == (RIPEM_CRLsPEMFrame *)NULL) {
      errorMessage = "Request CRLs not initialized";
      break;
    }
    stream = &frame->outStream;
  
    /* Get ready to write to the output. */
    BufferStreamRewind (stream);

    /* Allocate buffer for DER and encode the name.
     */
    if ((der = (unsigned char *)malloc (len_distinguishedname (name) + 4))
        == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    derPointer = der;
    DistinguishedNameToDER (name, &derPointer);

    /* Put out Issuer: tag. */
    if ((errorMessage = BufferStreamPuts (ISSUER_FIELD, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferCodeAndWriteBytes
         (der, (unsigned int)(derPointer - der), " ", stream)) != (char *)NULL)
      break;

    /* Set the output. */
    *partOut = stream->buffer;
    *partOutLen = stream->point;
  } while (0);

  free (der);
  return (errorMessage);
}

/* Finalize a CRL retrieval request message by outputting end message
     boundary.
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   Returns NULL for success, otherwise error string.
 */
char *RIPEMRequestCRLsFinal (ripemInfo, partOut, partOutLen)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
{
  RIPEM_CRLsPEMFrame *frame;
  BufferStream *stream;
  char *errorMessage;
  
  frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
  if (frame == (RIPEM_CRLsPEMFrame *)NULL)
    return ("Request CRLs not initialized");
  stream = &frame->outStream;
  
  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  if ((errorMessage = BufferStreamPuts (HEADER_STRING_END, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
    return (errorMessage);

  *partOut = stream->buffer;
  *partOutLen = stream->point;

  return ((char *)NULL);
}

/* This sets output and outputLen to the result of calling RIPEMPublishCRLInit
     and RIPEMPublishCRLFinal.  See RIPEMPublishCRLInit for details.
     This is provided only for backward compatibility with earlier versions
     of the RIPEM library API.
   Returns NULL for success, otherwise error string.
 */
char *RIPEMPublishCRL
  (ripemInfo, output, outputLen, messageFormat, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **output;
unsigned int *outputLen;
int messageFormat;
RIPEMDatabase *ripemDatabase;
{
  RIPEM_CRLsPEMFrame *frame;
  char *errorMessage;

  /* Note that output and outputLen will be modified below. */
  if ((errorMessage = RIPEMPublishCRLInit
       (ripemInfo, output, outputLen, messageFormat, ripemDatabase))
      != (char *)NULL)
    return (errorMessage);

  /* Don't call RIPEMPublishCRLFinal since it will rewind the buffer
       stream.  Instead, just duplicate its function here.
   */
  frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
  if ((errorMessage = BufferStreamPuts (HEADER_STRING_END, &frame->outStream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (&frame->outStream)) != (char *)NULL)
    return (errorMessage);

  /* Set the output. */
  *output = frame->outStream.buffer;
  *outputLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Initializes a CRL message containing the CRL for the user in ripemInfo.
   This adds Originator-Certificate and Issuer-Certificate fields if
     possible.  If messageFormat is MESSAGE_FORMAT_PEM and there is only
     one issuer chain, then Originator-Certificate has the certificate from
     that issuer.  Otherwise Originator-Certificate has the user's self-
     signed certificate.  This is the same technique used when enciphering
     a message.
   This returns an error if the CRL cannot be found or the signature is
     corrupt.  Otherwise, if the CRL is expired, it is still used.
   This returns a pointer to the output in partOut and its length in
     PartOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   After this, call RIPEMPublishCRLUpdate to include extra certs in the
     output, and call RIPEMPublishCRLFinal to finish.
   Returns NULL for success, otherwise error string.
 */
char *RIPEMPublishCRLInit
  (ripemInfo, partOut, partOutLen, messageFormat, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
int messageFormat;
RIPEMDatabase *ripemDatabase;
{
  RIPEM_CRLsPEMFrame *frame;
  BufferStream *stream;
  char *errorMessage;
  unsigned char *crlDER = (unsigned char *)NULL;
  int crlLen;
  
  /* Make sure any old frame is deleted and make a new one.
   */
  if (ripemInfo->z.crlsFrame != (RIPEM_CRLsFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.crlsFrame->Destructor) (ripemInfo->z.crlsFrame);
    free (ripemInfo->z.crlsFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEM_CRLsPEMFrame */
  if ((ripemInfo->z.crlsFrame = (RIPEM_CRLsFrame *)malloc
       (sizeof (*frame))) == (RIPEM_CRLsFrame *)NULL)
    return (ERR_MALLOC);
  RIPEM_CRLsPEMFrameConstructor
    ((RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame);

  /* Get stream for quick access. */
  frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  /* For error, break to end of do while (0) block. */
  do {
    if ((errorMessage = GetLoggedInLatestCRL
         (&crlDER, &crlLen, ripemInfo, ripemDatabase)) != (char *)NULL)
      break;

    /* Put out header indicating encapsulated message follows. */
    if ((errorMessage = BufferStreamPuts (HEADER_STRING_BEGIN, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    /* Put out field indicating processing type. */
    if ((errorMessage = BufferStreamPuts (PROC_TYPE_FIELD, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (PROC_TYPE_PEM_ID, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts
         (IDNames[PROC_TYPE_CRL_ID_ENUM], stream)) != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    /* Output the CRL. */
    if ((errorMessage = BufferStreamPuts (CRL_FIELD, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferCodeAndWriteBytes
         (crlDER, (unsigned int)crlLen, " ", stream)) != (char *)NULL)
      break;
    
    if ((errorMessage = WriteOriginatorAndIssuerCerts
         (ripemInfo, stream, messageFormat)) != (char *)NULL)
      break;

    /* Set the output. */
    *partOut = stream->buffer;
    *partOutLen = stream->point;
  } while (0);

  free (crlDER);
  return (errorMessage);
}

/* Call this after RIPEMPublishCRLInit.  This may be called zero or more
     times to add extra certificates to the CRL message.  This is not
     explicitly permitted by the PEM RFCs, but it is a way to export
     certificates for other user's to import into their database.  Note that
     this can be called an arbitrarily large number of times (especially
     using the RIPEMDatabaseCursor) without overrunning memory.
   This adds an "Issuer-Certificate" field for each entry in the certs list.
   See RIPEMPublishCRLInit for a description of partOut and partOutLen.
   Return NULL for success or error string.
 */
char *RIPEMPublishCRLUpdate (ripemInfo, partOut, partOutLen, certs)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
TypList *certs;
{
  TypListEntry *entry;
  RIPEM_CRLsPEMFrame *frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
  char *errorMessage;
  
  if (frame == (RIPEM_CRLsPEMFrame *)NULL)
    return ("Publish CRL not initialized");
  if (frame->ripemCRLsFrame.Destructor != 
      (RIPEM_CRLS_FRAME_DESTRUCTOR)RIPEM_CRLsPEMFrameDestructor)
    return ("CRLs frame was not initialized by RIPEMPublishCRLInit");

  /* Get ready to write to the output. */
  BufferStreamRewind (&frame->outStream);

  for (entry = certs->firstptr; entry; entry = entry->nextptr) {
    if ((errorMessage = BufferStreamPuts
         (ISSUER_CERT_FIELD, &frame->outStream)) != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = WriteEOL (&frame->outStream)) != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = BufferCodeAndWriteBytes
         ((unsigned char *)entry->dataptr, entry->datalen, " ",
          &frame->outStream)) != (char *)NULL)
      return (errorMessage);  
  }

  /* Set the output. */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Call this after RIPEMPublishCRLInit and zero or more calls to
     RIPEMPublishCRLUpdate.  This flushes the output and writes the end
     message boundary.  See RIPEMPublishCRLInit for a description of
     partOut and partOutLen.
   Return NULL for success or error string.
 */
char *RIPEMPublishCRLFinal (ripemInfo, partOut, partOutLen)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
{
  RIPEM_CRLsPEMFrame *frame = (RIPEM_CRLsPEMFrame *)ripemInfo->z.crlsFrame;
  char *errorMessage;
  
  if (frame == (RIPEM_CRLsPEMFrame *)NULL)
    return ("Publish CRL not initialized");
  if (frame->ripemCRLsFrame.Destructor != 
      (RIPEM_CRLS_FRAME_DESTRUCTOR)RIPEM_CRLsPEMFrameDestructor)
    return ("CRLs frame was not initialized by RIPEMPublishCRLInit");

  /* Get ready to write to the output. */
  BufferStreamRewind (&frame->outStream);

  if ((errorMessage = BufferStreamPuts (HEADER_STRING_END, &frame->outStream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (&frame->outStream)) != (char *)NULL)
    return (errorMessage);

  /* Set the output. */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

void RIPEMEncipherPEMFrameConstructor (frame)
RIPEMEncipherPEMFrame *frame;
{
  /* Must set the pointer to the virtual destructor */
  frame->ripemEncipherFrame.Destructor =
    (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPEMFrameDestructor;

  BufferStreamConstructor (&frame->outStream);
  frame->encryptedKeysBuffer = (unsigned char *)NULL;
  frame->encryptedKeyLens = (unsigned int *)NULL;
  InitList (&frame->issuerNames);
  frame->wroteHeader = FALSE;
  frame->lastWasNewline = FALSE;
  BufferStreamConstructor (&frame->buffer);
}

void RIPEMEncipherPEMFrameDestructor (frame)
RIPEMEncipherPEMFrame *frame;
{
  BufferStreamDestructor (&frame->outStream);
  BufferStreamDestructor (&frame->buffer);
  free (frame->encryptedKeysBuffer);
  free (frame->encryptedKeyLens);
  R_memset ((POINTER)&frame->sealContext, 0, sizeof (frame->sealContext));
  R_memset
    ((POINTER)&frame->signatureContext, 0, sizeof (frame->signatureContext));
}

void RIPEMDecipherPEMFrameConstructor (frame)
RIPEMDecipherPEMFrame *frame;
{
  /* Must set the pointer to the virtual destructor */
  frame->ripemDecipherFrame.Destructor =
    (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPEMFrameDestructor;

  BufferStreamConstructor (&frame->outStream);
  TypMsgInfoConstructor (&frame->messageInfo);
  BufferStreamConstructor (&frame->lineIn);
  frame->doingHeader = TRUE;
  frame->foundEndBoundary = FALSE;
  InitList (&frame->headerList);
  InitList (&frame->certChain);
}

void RIPEMDecipherPEMFrameDestructor (frame)
RIPEMDecipherPEMFrame *frame;
{
  BufferStreamDestructor (&frame->outStream);
  TypMsgInfoDestructor (&frame->messageInfo);
  BufferStreamDestructor (&frame->lineIn);
  R_memset ((POINTER)frame->decryptedLine, 0, sizeof (frame->decryptedLine));
  R_memset ((POINTER)frame->signature, 0, sizeof (frame->signature));
  R_memset
    ((POINTER)&frame->envelopeContext, 0, sizeof (frame->envelopeContext));
  R_memset
    ((POINTER)&frame->signatureContext, 0, sizeof (frame->signatureContext));
  frame->foundEndBoundary = FALSE;
  FreeList (&frame->headerList);
  FreeList (&frame->certChain);
}

void RIPEM_CRLsPEMFrameConstructor (frame)
RIPEM_CRLsPEMFrame *frame;
{
  /* Must set the pointer to the virtual destructor */
  frame->ripemCRLsFrame.Destructor =
    (RIPEM_CRLS_FRAME_DESTRUCTOR)RIPEM_CRLsPEMFrameDestructor;

  BufferStreamConstructor (&frame->outStream);
}

void RIPEM_CRLsPEMFrameDestructor (frame)
RIPEM_CRLsPEMFrame *frame;
{
  BufferStreamDestructor (&frame->outStream);
}

/*  Write the Privacy Enhanced Mail header.
    Entry:   ripemInfo contains the enhance frame with the information
              to output
            frame->stream    is the I/O stream to write to.
            frame->iv        is the init vector that was used to encrypt.
            frame->recipientKeys contains the recipient public keys
            frame->encryptedKeysBuffer contains the concatenated encrypted
             DEKs, where each takes MAX_ENCRYPTED_KEY_LEN bytes in the buffer.
           frame->encryptedKeyLens is the actual length of each encrypted DEK.
            frame->recipientKeyCount is the number of recipients.
            encryptedSignature      is the signature, possibly encrypted.
            encryptedSignatureLen is the number of bytes in above.
   ripemDatabase is used for selecting certificates to find issuer names
     and serial numbers of recipients for MESSAGE_FORMAT_PEM.
 
   Exit:    We have written the header out to the stream, followed
              by a blank line.
            This will prencode the signature and recipient key infos.
            Returns NULL if no error, else error message.
 */
static char *WriteHeader
  (ripemInfo, encryptedSignature, encryptedSignatureLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char *encryptedSignature;
unsigned int encryptedSignatureLen;
RIPEMDatabase *ripemDatabase;
{
  RIPEMEncipherPEMFrame *frame =
    (RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  TypListEntry *entry;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  char *errorMessage;
  char iv_hex[2 * IV_SIZE + 1];
  unsigned char *der = (unsigned char *)NULL;
  unsigned int derLen, i;
  enum enum_ids enhanceMode;
  TypList certList;

  InitList (&certList);
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Convert enum enhance_mode to enum_ids.
     */
    if (frame->enhanceMode == MODE_ENCRYPTED)
      enhanceMode = PROC_TYPE_ENCRYPTED_ID_ENUM;
    else if (frame->enhanceMode == MODE_MIC_ONLY)
      enhanceMode = PROC_TYPE_MIC_ONLY_ID_ENUM;
    else
      enhanceMode = PROC_TYPE_MIC_CLEAR_ID_ENUM;

    /* Get stream pointer by itself for convenience. */
    stream = &frame->outStream;

    /* Put out header indicating encapsulated message follows. */
    if ((errorMessage = BufferStreamPuts (HEADER_STRING_BEGIN, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    /* Put out field indicating processing type. */
    if ((errorMessage = BufferStreamPuts (PROC_TYPE_FIELD, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts
         (frame->messageFormat == MESSAGE_FORMAT_RIPEM1 ?
          PROC_TYPE_RIPEM_ID : PROC_TYPE_PEM_ID, stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
      break;

    if ((errorMessage = BufferStreamPuts (IDNames[enhanceMode], stream))
        != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    /* Put out content domain. */
    if ((errorMessage = BufferStreamPuts (CONTENT_DOMAIN_FIELD, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (" RFC822", stream)) != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    /* If encrypting, put out DEK-Info field. */
    if (enhanceMode == PROC_TYPE_ENCRYPTED_ID_ENUM) {
      if ((errorMessage = BufferStreamPuts (DEK_FIELD, stream))
          != (char *)NULL)
        break;
      if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
        break;
      if (frame->encryptionAlgorithm == EA_DES_EDE2_CBC) {
        if ((errorMessage = BufferStreamPuts (DEK_ALG_TDES_CBC_ID, stream))
            != (char *)NULL)
          break;
      }
      else {
        if ((errorMessage = BufferStreamPuts (DEK_ALG_DES_CBC_ID, stream))
            != (char *)NULL)
          break;
      }
      if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
        break;
      BinToHex (frame->iv, IV_SIZE, iv_hex);
      if ((errorMessage = BufferStreamPuts (iv_hex, stream)) != (char *)NULL)
        break;
      if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
        break;
    }

    if (frame->messageFormat == MESSAGE_FORMAT_RIPEM1) {
      /* Write Originator's name. */

      if ((errorMessage = BufferStreamPuts (SENDER_FIELD, stream))
          != (char *)NULL)
        break;
      if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
        break;
      if ((errorMessage = BufferStreamPuts
           (GetDNSmartNameValue (&ripemInfo->userDN), stream)) != (char *)NULL)
        break;
      if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
        break;
    }

    if ((errorMessage = WriteOriginatorAndIssuerCerts
         (ripemInfo, stream, frame->messageFormat)) != (char *)NULL)
      break;

    /* Write out the digital signature.
     */
    if ((errorMessage = BufferStreamPuts (MIC_INFO_FIELD, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
      break;

    if (frame->digestAlgorithm == DA_MD2) {
      if ((errorMessage = BufferStreamPuts
           (MIC_MD2_ID, stream)) != (char *)NULL)
        break;
    }
    else if (frame->digestAlgorithm == DA_MD5) {
      if ((errorMessage = BufferStreamPuts
           (MIC_MD5_ID, stream)) != (char *)NULL)
        break;
    }
    else if (frame->digestAlgorithm == DA_SHA1) {
      if ((errorMessage = BufferStreamPuts
           (MIC_SHA1_ID, stream)) != (char *)NULL)
        break;
    }
    else {
      /* This shouldn't happen because R_SignInit has checked it. */
      errorMessage = "Unsupported digest algorithm";
      break;
    }

    if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (ENCRYPTION_ALG_RSA_ID, stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    if ((errorMessage = BufferCodeAndWriteBytes
         (encryptedSignature, encryptedSignatureLen, " ", stream))
        != (char *)NULL)
      break;

    if (enhanceMode == PROC_TYPE_ENCRYPTED_ID_ENUM) {
      /* Allocate the certStruct on the heap because it's big. */
      if ((certStruct = (CertificateStruct *)malloc
           (sizeof (*certStruct))) == (CertificateStruct *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }
      
      /* For each recipient, write out the recipient identifier and
           encrypted message key.
       */
      for (i = 0; i < frame->recipientKeyCount; ++i) {
        if (frame->messageFormat == MESSAGE_FORMAT_RIPEM1) {
          /* Write user name (email address) */
          if ((errorMessage = BufferStreamPuts (RECIPIENT_FIELD, stream))
              != (char *)NULL)
            break;
          if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
            break;
          if ((errorMessage = BufferStreamPuts
               (frame->recipientKeys[i].username, stream)) != (char *)NULL)
            break;
          if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
            break;

          /* Write the recipient's public key */
          if ((errorMessage = BufferStreamPuts (RECIPIENT_KEY_FIELD, stream))
              != (char *)NULL)
            break;
          if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
            break;

          derLen = PubKeyToDERLen (&frame->recipientKeys[i].publicKey);
          /* Use realloc since we reuse this buffer in this loop. */
          if ((der = (unsigned char *)R_realloc (der, derLen + 1))
              == (unsigned char *)NULL) {
            errorMessage = ERR_MALLOC;
            break;
          }
          PubKeyToDER (&frame->recipientKeys[i].publicKey, der, &derLen);
          if ((errorMessage = BufferCodeAndWriteBytes
               (der, derLen, " ", stream)) != (char *)NULL)
            break;

          /* Write encrypted message key. */
          if ((errorMessage = WriteKeyInfo
               (frame->encryptedKeysBuffer + i * MAX_ENCRYPTED_KEY_LEN,
                frame->encryptedKeyLens[i], stream)) != (char *)NULL)
            break;
        }

        if (frame->messageFormat == MESSAGE_FORMAT_PEM) {
          /* For every certificate we can find with a matching
               username and public key, write its issuer name and serial
               number as a Recipient-ID-Asymmetric and its accompanying
               Key-Info.
           */
          /* Free any previous contents of certList */
          FreeList (&certList);

          if ((errorMessage = GetCertsBySmartname
               (ripemDatabase, &certList, frame->recipientKeys[i].username,
                ripemInfo)) != (char *)NULL)
            break;
          for (entry = certList.firstptr; entry; entry = entry->nextptr) {
            /* Decode the certificate.  On failure, just warn and continue.
             */
            if (DERToCertificate
                ((unsigned char *)entry->dataptr, certStruct,
                 (CertFieldPointers *)NULL) < 0) {
              /* Error decoding.  Just issue a warning to debug stream and try
                 the next cert. */
              if (ripemInfo->debug > 1)
                fprintf (ripemInfo->debugStream,
 "Warning: Cannot decode certificate from database for writing Recipient-ID.\n");
              continue;
            }
            
            if (R_memcmp
                ((POINTER)&frame->recipientKeys[i].publicKey,
                 (POINTER)&certStruct->publicKey,
                 sizeof (certStruct->publicKey)) != 0)
              /* Not the same public key.  Try the next */
              continue;

            if ((errorMessage = WriteRecipientIDAsymmetric
                 (&certStruct->issuer, certStruct->serialNumber,
                  sizeof (certStruct->serialNumber), stream)) != 0)
              break;
            /* Write encrypted message key. */
            if ((errorMessage = WriteKeyInfo
                 (frame->encryptedKeysBuffer + i * MAX_ENCRYPTED_KEY_LEN,
                  frame->encryptedKeyLens[i], stream)) != (char *)NULL)
              break;
          }
          if (errorMessage != (char *)NULL)
            /* Broke loop because of error. */
            break;
        }
      }
      if (errorMessage != (char *)NULL)
        /* Broke loop because of error. */
        break;
    }

    /* Write blank line that separates headers from text. */
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;
  } while (0);

  free (der);
  FreeList (&certList);
  free (certStruct);
  return (errorMessage);
}

static char *WriteKeyInfo (encryptedKey, encryptedKeyLen, stream)
unsigned char *encryptedKey;
unsigned int encryptedKeyLen;
BufferStream *stream;
{
  char *errorMessage;
  
  if ((errorMessage = BufferStreamPuts (MESSAGE_KEY_FIELD, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPuts (ENCRYPTION_ALG_RSA_ID, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferCodeAndWriteBytes
       (encryptedKey, encryptedKeyLen, " ", stream)) != (char *)NULL)
    return (errorMessage);
  return ((char *)NULL);
}

static char *WriteRecipientIDAsymmetric
  (issuerName, serialNumber, serialNumberLen, stream)
DistinguishedNameStruct *issuerName;
unsigned char *serialNumber;
unsigned int serialNumberLen;
BufferStream *stream;
{
  char *errorMessage, *hex = (char *)NULL;
  unsigned char *der = (unsigned char *)NULL, *derPointer,
    *zero = (unsigned char *)"";

  /* For error, break to end of do while (0) block. */
  do {
    if ((errorMessage = BufferStreamPuts
         (RECIPIENT_ID_ASYMMETRIC_FIELD, stream)) != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;

    /* Allocate buffer and convert issuer name to DER and write it.
     */
    if ((der = (unsigned char *)malloc
         (len_distinguishedname (issuerName) + 4)) == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    derPointer = der;
    DistinguishedNameToDER (issuerName, &derPointer);
    if ((errorMessage = BufferCodeAndWriteBytes
         (der, (unsigned int)(derPointer - der), " ", stream)) != (char *)NULL)
      break;
    
    /* Strip leading zeroes off serialNumber. */
    while ((serialNumberLen > 0) && (*serialNumber == 0)) {
      ++serialNumber;
      --serialNumberLen;
    }
    if (serialNumberLen == 0) {
      /* Make sure there is a zero byte */
      serialNumber = zero;
      serialNumberLen = 1;
    }

    /* Allocate array and write hex serial number.  Don't forget the " ,".
     */
    if ((hex = malloc (2 * serialNumberLen + 1)) == (char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    BinToHex (serialNumber, serialNumberLen, hex);
    if ((errorMessage = BufferStreamPuts (" ", stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (SPEC_SEP, stream)) != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamPuts (hex, stream)) != (char *)NULL)
      break;
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      break;
  } while (0);

  free (der);
  free (hex);
  return (errorMessage);
}

/* Process the enhanced text line, decoding and decrpyting if needed,
     call R_VerifyUpdate with signatureContext, and write out the result to
     outStream.
   The signatureContext must already be initialized.  On return, the
     caller can call R_VerifyFinal when frame->foundEndBoundary is set. 
   If the frame's messageInfo.proc_type is not MIC-CLEAR, decode the input,
     otherwise strip "- " from lines that begin with "- -" and adding CR/LF
     to the end of line for calling R_VerifyUpdate.
   If the frame's messageInfo.proc_type is ENCRYPTED, envelopeContext must
     already be initialized. Use it to decrypt the content.
   When we encounter the PEM end boundary line, set frame->foundEndBoundary.
     After this is set, all further calls to this routine do nothing.
 */
static char *ReadEnhancedTextLine (frame, outStream, line)
RIPEMDecipherPEMFrame *frame;
BufferStream *outStream;
char *line;
{
  unsigned char *linecp;
  char *errorMessage;
  int status;
  unsigned int decodedLineLen, lineLen, linecpLen;

  if (frame->foundEndBoundary)
    /* We are reading past the end boundary, so ignore. */
    return ((char *)NULL);

  if (strncmp ((char *)line, HEADER_STRING_END, HEADER_STRING_END_LEN) == 0) {
    /* Reached the end PEM boundary.  If we are decrypting we
         must process the final block.
     */
    if (frame->messageInfo.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM) {
      /* Finalize to decryptedLine, setting linecpLen to the length. */
      if ((status = R_OpenFinal
           (&frame->envelopeContext, frame->decryptedLine, &linecpLen))
          != 0)
        return (FormatRSAError (status));
      if ((status = R_VerifyUpdate
           (&frame->signatureContext, frame->decryptedLine, linecpLen))
          != 0)
        return (FormatRSAError (status));
      if ((errorMessage = WriteMessage
           (frame->decryptedLine, linecpLen, FALSE, outStream))
          != (char *)NULL)
        return (errorMessage);
    }

    /* Done, so set end flag and return. */
    frame->foundEndBoundary = TRUE;
    return ((char *)NULL);
  }

  /* Determine line length as characters up to end-of-line CR and/or NL */
  for (lineLen = 0;
       line[lineLen] != '\0' && line[lineLen] != '\r' && line[lineLen] != '\n';
       ++lineLen);

  if (frame->messageInfo.proc_type != PROC_TYPE_MIC_CLEAR_ID_ENUM) {
    /* Strip whitespace from the end of the encoded line. */
    while (lineLen > 0 && WhiteSpace (line[lineLen - 1]))
      --lineLen;

    /* Decode the line in place.  This will work since the output
         of decoding is smaller than the input.
       Note: this assumes the input is a multiple of 4 bytes.
     */
    if ((status = R_DecodePEMBlock
         ((unsigned char *)line, &decodedLineLen, (unsigned char *)line,
          lineLen)) != 0)
      return (FormatRSAError (status));

    if (frame->messageInfo.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM) {
      /* Decrypt to decryptedLine, setting linecpLen to the length. */
      if ((status = R_OpenUpdate
           (&frame->envelopeContext, frame->decryptedLine, &linecpLen,
            (unsigned char *)line, decodedLineLen)) != 0)
        return (FormatRSAError (status));

      linecp = frame->decryptedLine;
    }
    else {
      /* Just point to the decoded line. */
      linecp = (unsigned char *)line;
      linecpLen = decodedLineLen;
    }

    /* linecp and linecpLen now have the result, so digest and write out.
       Note that WriteMessage will convert the CR/LF correctly to
         local format.
     */
    if ((status = R_VerifyUpdate
         (&frame->signatureContext, linecp, linecpLen)) != 0)
      return (FormatRSAError (status));
    if ((errorMessage = WriteMessage (linecp, linecpLen, FALSE, outStream))
        != (char *)NULL)
      return (errorMessage);
  }
  else {
    /* Strip quoted hyphens. */
    if (strncmp (line, "- -", 3) == 0) {
      line += 2;
      lineLen -= 2;
    }

    /* Digest the line plus CR/LF */
    if ((status = R_VerifyUpdate
         (&frame->signatureContext, (unsigned char *)line, lineLen)) != 0)
      return (FormatRSAError (status));
    if ((status = R_VerifyUpdate
         (&frame->signatureContext, (unsigned char *)"\015\012", 2)) != 0)
      return (FormatRSAError (status));

    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)line, lineLen, outStream)) != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = WriteEOL (outStream)) != (char *)NULL)
      return (errorMessage);
  }

  return ((char *)NULL);
}

/* Process the header and set the ripemInfo's frame's signature,
     certChain, etc.  If this finds an unvalidated self-signed certificate,
     it sets frame->foundEndBoundary to prevent processing of the text.
   outStream is for writing the prepended headers.
 */
static char *ProcessHeader (ripemInfo, outStream, ripemDatabase)
RIPEMInfo *ripemInfo;
BufferStream *outStream;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage = (char *)NULL;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  int isSelfSigned, status, certLen;
  BOOL found;
  void *certCopy;
  TypListEntry *entry;
  RIPEMDecipherPEMFrame *frame;

  /* For error, break to end of do while (0) block. */
  do {
    frame = (RIPEMDecipherPEMFrame *)ripemInfo->z.decipherFrame;

    if (frame->messageInfo.proc_type == PROC_TYPE_CRL_ID_ENUM) {
      /* CRL message.  The certificates have already been inserted into the
           database.  Also, the CRL should have been inserted one at a time
           after the associated certificates.  If there is a remaining CRL,
           we must insert it here.
       */
      if (frame->messageInfo.crlToInsert != (unsigned char *)NULL) {
        if ((errorMessage = VerifyAndInsertCRL
             (frame->messageInfo.crlToInsert, ripemInfo, ripemDatabase))
            != (char *)NULL)
          break;
        free (frame->messageInfo.crlToInsert);
        frame->messageInfo.crlToInsert = (unsigned char *)NULL;
      }

      /* We have inserted the certs and CRLs, so break.
         Setting foundEndBoundary will prevent the processing of
           any more of the message. */
      frame->foundEndBoundary = TRUE;
      break;
    }

    if (!frame->messageInfo.msg_key &&
        frame->messageInfo.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM) {
      errorMessage = "You are not listed as a recipient in this message.";
      break;
    }
    if (ripemInfo->debug > 1) {
      fprintf
        (ripemInfo->debugStream,"From input encapsulated message header:\n");
      fprintf
        (ripemInfo->debugStream,"  Proc-Type = %s",
         IDNames[frame->messageInfo.proc_type]);
      if(frame->messageInfo.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM) {
        char ivhex[20];
        char hex_digest[36];

        BinToHex(frame->messageInfo.iv,8,ivhex);
        fprintf(ripemInfo->debugStream,"  DES iv = %s",ivhex);

        MakeHexDigest
          (frame->messageInfo.msg_key, frame->messageInfo.msg_key_len,
           hex_digest);
        fprintf
          (ripemInfo->debugStream," Digest of Encrypted Key = %s\n",
           hex_digest);
      }
      fprintf(ripemInfo->debugStream,"\n");
      if(frame->messageInfo.orig_name) {
        fprintf(ripemInfo->debugStream,"  Originator-Name = %s\n",
                frame->messageInfo.orig_name);
      }
      fprintf
        (ripemInfo->debugStream,"  %s Originator's public key in header.\n",
         frame->messageInfo.got_orig_pub_key ? "Got" : "Didn't get");
      fprintf
        (ripemInfo->debugStream,"  %d bytes in encoded & encrypted MIC:\n",
         frame->messageInfo.mic_len);
      fprintf(ripemInfo->debugStream,"   %s\n", frame->messageInfo.mic);
      if(frame->messageInfo.msg_key) {
        fprintf
          (ripemInfo->debugStream,
           "  %d bytes in encoded & encrypted message key:\n",
           frame->messageInfo.msg_key_len);
        fprintf
          (ripemInfo->debugStream,"   %s\n", frame->messageInfo.msg_key);
      }
    }

    if (frame->messageInfo.originatorCert != (unsigned char *)NULL) {
      /* This is a certificate-based message.  All certificates have been
           inserted into the database.
       */
      if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
          == (CertificateStruct *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      /* Decode originator cert. */
      if ((certLen = DERToCertificate
           (frame->messageInfo.originatorCert, certStruct, &fieldPointers))
          < 0) {
        errorMessage = "Cannot decode originator certificate";
        break;
      }

      /* Try to get the sender's cert chain.  We set directCertOnly
           FALSE to allow any chain. */
      if ((errorMessage = SelectCertChain
           (ripemInfo, &frame->certChain, &frame->chainStatus,
            &certStruct->subject, &certStruct->publicKey, FALSE,
            ripemDatabase)) != (char *)NULL)
        break;

      if (frame->chainStatus.overall == 0) {
        /* Couldn't find a chain, so try to process a self-signed cert.
         */
        CheckSelfSignedCert
          (&isSelfSigned, certStruct, fieldPointers.innerDER,
           fieldPointers.innerDERLen);

        if (isSelfSigned) {
          /* Copy the self-signed cert to the cert chain.
             The certChain should be empty now.
             Note that chainStatus.overall is still 0.
           */
          if ((certCopy = malloc (certLen)) == NULL) {
            errorMessage = ERR_MALLOC;
            break;
          }
          R_memcpy
            ((POINTER)certCopy, (POINTER)frame->messageInfo.originatorCert,
             certLen);
          if ((errorMessage = PrependToList
               (certCopy, certLen, &frame->certChain)) != (char *)NULL) {
            /* Free the cert copy we just allocated */
            free (certCopy);
            break;
          }

          /* We have copied the self-signed cert, so break.
             Setting foundEndBoundary will prevent the processing of
               the message text. */
          frame->foundEndBoundary = TRUE;
          break;
        }
        else {
          /* Can't find a chain and this is not a self-signed cert,
               so just return error. */
          errorMessage = "Cannot find certificate chain for sender.";
          break;
        }
      }

      /* Decode the cert at the "bottom" of the chain and point the
           public key to it.  Note DERToCertificate won't return an error
           since it was already successfully decoded.
       */
      DERToCertificate
        ((unsigned char *)frame->certChain.firstptr->dataptr, certStruct,
         (CertFieldPointers *)NULL);
      frame->senderKey = certStruct->publicKey;
    }
    else {
      /* Process non-certificate based message */
      frame->chainStatus.overall = CERT_UNVALIDATED;

      if(!frame->messageInfo.orig_name) {
        errorMessage = "Can't find Originator's name in message.";
        break;
      }

      /* Copy the originator's name as the entry in the "certChain" */
      if ((errorMessage = AppendLineToList
           (frame->messageInfo.orig_name, &frame->certChain)) != (char *)NULL)
        break;

      /* Obtain the sender's public key. */

      errorMessage = GetUnvalidatedPublicKey
        (frame->messageInfo.orig_name, &ripemDatabase->pubKeySource,
         &frame->senderKey, &found, ripemInfo);

      if (errorMessage || !found) {
        if (frame->messageInfo.got_orig_pub_key) {
          if (ripemInfo->debug > 0) {
            if (!errorMessage) {
              fprintf(ripemInfo->debugStream,
                      "Warning: public key of \"%s\" not on file.\n",
                      frame->messageInfo.orig_name);
            }
            else {
              fprintf
                (ripemInfo->debugStream,
                 "Warning: problem encountered with public key of \"%s\":\n",
                 frame->messageInfo.orig_name);
              fprintf(ripemInfo->debugStream,"  %s\n",errorMessage);
            }

            fprintf (ripemInfo->debugStream,"Using key supplied in message.\n");
          }
          frame->senderKey = frame->messageInfo.orig_pub_key;
          ripemInfo->z.used_pub_key_in_message = 1;
        }
        else {
          /* Don't have a public key */
          if (errorMessage == (char *)NULL)
            /* Setting foundEndBoundary will prevent the processing of
               the message text. */
            frame->foundEndBoundary = TRUE;
          break;
        }
      } else {
        /* frame->senderKey already has the public key.
           Check to make sure that the sender's public key in the
             message header matches the sender's recorded public key.
         */
        if(frame->messageInfo.got_orig_pub_key) {
          if(R_memcmp((POINTER)&frame->messageInfo.orig_pub_key,
                      (POINTER)&frame->senderKey,
                      sizeof (frame->senderKey))) {
            fprintf(ripemInfo->debugStream,
                    "Warning: %s's public key in message does not match retrieved value.\n",
                    frame->messageInfo.orig_name);
          }
        }
      }
    }

    /* Write out the original message header if requested. */
    if (frame->prependHeaders) {
      /* Copy the headers to the output. */
      for (entry = frame->headerList.firstptr; entry;
           entry = entry->nextptr) {
        if ((errorMessage = BufferStreamPuts
             ((char *)entry->dataptr, outStream)) != (char *)NULL)
          break;
        if ((errorMessage = WriteEOL (outStream)) != (char *)NULL)
          break;
      }
      if (frame->headerList.firstptr != (TypListEntry *)NULL) {
        /* There were in fact lines, so put a blank line */
        if ((errorMessage = WriteEOL (outStream)) != (char *)NULL)
          break;
      }
    }

    if (frame->messageInfo.proc_type == PROC_TYPE_ENCRYPTED_ID_ENUM) {
#ifdef RIPEMSIG
      errorMessage = "RIPEM/SIG cannot process ENCRYPTED messages. You may process signed messages.";
      break;
#else
      if(ripemInfo->debug>1) {
        char hex_digest[36], line[120];

        fprintf(ripemInfo->debugStream,
                "Decrypting.    keyLen=%u, sigLen=%u, user=%s\n",
                frame->messageInfo.msg_key_len, frame->messageInfo.mic_len,
                GetDNSmartNameValue (&ripemInfo->userDN));
        MakeHexDigest(frame->messageInfo.msg_key,
                      frame->messageInfo.msg_key_len,hex_digest);
        fprintf
          (ripemInfo->debugStream," MD5 of Encrypted Key     = %s\n",
           hex_digest);
        MakeHexDigest
          (frame->messageInfo.mic, frame->messageInfo.mic_len, hex_digest);
        fprintf
          (ripemInfo->debugStream," MD5 of encrypted signat. = %s\n",
           hex_digest);
        fprintf(ripemInfo->debugStream,"  Encrypted, encoded MIC =\n");
        WriteCoded
          (frame->messageInfo.mic, frame->messageInfo.mic_len, "   ",
           ripemInfo->debugStream);
        BinToHex(frame->messageInfo.iv,8,line);
        fprintf
          (ripemInfo->debugStream," Initializing vector      = %s DigAlg=%d\n",
           line,frame->messageInfo.da);
      }

      /* Initialize envelopeContext and decrypt signature.
       */
      if ((status = RIPEMOpenInit
           (ripemInfo, &frame->envelopeContext, frame->signature,
            &frame->signatureLen)) != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
#endif /* end RIPEMSIG */
    }
    else if (frame->messageInfo.proc_type == PROC_TYPE_MIC_ONLY_ID_ENUM ||
             frame->messageInfo.proc_type == PROC_TYPE_MIC_CLEAR_ID_ENUM) {
      /* Just decode the signature.
       */
      if (frame->messageInfo.mic_len > MAX_PEM_SIGNATURE_LEN) {
        errorMessage = "Signature in header is too long.";
        break;
      }

      if ((status = R_DecodePEMBlock
           (frame->signature, &frame->signatureLen, frame->messageInfo.mic,
            frame->messageInfo.mic_len)) != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
    }
    else {
      errorMessage = "Invalid message proc type";
      break;
    }
  } while (0);
  
  free (certStruct);
  return (errorMessage);
}

/* The encipher frame's signature context has been updated, so finalize
     signature and write out the PEM header.
   This does not rewind the outStream.
   ripemDatabase only used for ENCRYPTED message.
 */
static char *SignFinalOutputHeader (ripemInfo, ripemDatabase)
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  RIPEMEncipherPEMFrame *frame =
    (RIPEMEncipherPEMFrame *)ripemInfo->z.encipherFrame;
  char *errorMessage = (char *)NULL;
  int status;
  unsigned char signature[MAX_PEM_ENCRYPTED_SIGNATURE_LEN];
  unsigned int signatureLen;
#ifndef RIPEMSIG
  unsigned int localPartOutLen;
#endif

  /* For error, break to end of do while (0) block. */
  do {
    if ((status = R_SignFinal
         (&frame->signatureContext, signature, &signatureLen,
          &ripemInfo->privateKey)) != 0) {
      errorMessage = FormatRSAError(status);
      break;
    }

    if (frame->enhanceMode == MODE_ENCRYPTED) {
#ifndef RIPEMSIG
      /* Encrypt the signature in place.
       */
      if ((status = R_SealUpdate
           (&frame->sealContext, signature, &signatureLen, signature,
            signatureLen)) != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
      if ((status = R_SealFinal
           (&frame->sealContext, signature + signatureLen, &localPartOutLen))
          != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
      signatureLen += localPartOutLen;
      
      if (ripemInfo->debug > 1) {
        char hex_digest[36];
        
        fprintf (ripemInfo->debugStream, "sigLen=%u (not recoded)\n",
                 signatureLen);
        MakeHexDigest(signature, signatureLen,hex_digest);
        fprintf
          (ripemInfo->debugStream," MD5 of encrypted signat. = %s\n",
           hex_digest);
      }

      /* Note: make sure we pass enum_ids for the enhanceMode. */
      if ((errorMessage = WriteHeader
           (ripemInfo, signature, signatureLen, ripemDatabase))
          != (char *)NULL)
        break;
#endif
    }
    else {
      /* Write out a header for a non-encrypted message.
         This will encode the signature and ignore the iv and recipient
           stuff.
         Note: make sure we pass enum_ids for the enhanceMode. */
      if ((errorMessage = WriteHeader
           (ripemInfo, signature, signatureLen, ripemDatabase))
          != (char *)NULL)
        break;
    }
  } while (0);

  R_memset ((POINTER)signature, 0, sizeof (signature));
  return (errorMessage);
}

/* quoteHyphens means add "- " before lines which start with a hyphen.
   This translates <CR><LF> to '\n'.
 */
static char *WriteMessage (text, textLen, quoteHyphens, stream)
unsigned char *text;
unsigned int textLen;
BOOL quoteHyphens;
BufferStream *stream;
{
  register int ch;
  char *errorMessage = (char *)NULL;
  
  if (quoteHyphens && textLen > 1 && *text == '-') {
    if ((errorMessage = BufferStreamPuts ("- ", stream)) != (char *)NULL)
      return (errorMessage);
  }

  while(textLen--) {
    ch = (int) *(text++);
    if(ch == '\015') {
      /* Ignore CR's */
    } else if (ch == '\012') {
      if ((errorMessage = WriteEOL(stream)) != (char *)NULL)
        return (errorMessage);
      if(quoteHyphens && textLen >= 1 && *text == '-') {
        if ((errorMessage = BufferStreamPuts ("- ", stream)) != (char *)NULL)
          return (errorMessage);
      }
    } else {
      if ((errorMessage = BufferStreamPutc (ch, stream)) != (char *)NULL)
        return (errorMessage);
    }
  }

  return ((char *)NULL);
}

/* Write Originator-Certificate and Issuer-Certificate fields to stream
     using userCertDER and issuerCerts in ripemInfo.
   If messageFormat is MESSAGE_FORMAT_PEM and there
     is only one issuer chain.  We will try to be more PEM-like by
     not outputting a self-signed certificate in the Originator-Certificate
     field.  If there are no issuer chains, or more than one, then we output
     the self-signed cert.
 */
static char *WriteOriginatorAndIssuerCerts (ripemInfo, stream, messageFormat)
RIPEMInfo *ripemInfo;
BufferStream *stream;
int messageFormat;
{
  TypListEntry *entry;
  BOOL useSinglePEMChain;
  char *errorMessage;

  useSinglePEMChain = (messageFormat == MESSAGE_FORMAT_PEM) &&
    (ripemInfo->z.issuerChainCount == 1);

  if (!useSinglePEMChain) {
    /* Write originator's self-signed certificate.
     */
    if ((errorMessage = BufferStreamPuts (ORIGINATOR_CERT_FIELD, stream))
        != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = BufferCodeAndWriteBytes
         (ripemInfo->z.userCertDER, ripemInfo->z.userCertDERLen, " ",
          stream)) != (char *)NULL)
      return (errorMessage);
  }

  /* Write the Issuer-Certificates.
   */
  for (entry = ripemInfo->issuerCerts.firstptr; entry;
       entry = entry->nextptr) {
    if (useSinglePEMChain && entry == ripemInfo->issuerCerts.firstptr) {
      /* This is the first cert in the one-and-only chain, and we are
           in PEM mode, so make this the Originator-Cert */
      if ((errorMessage = BufferStreamPuts (ORIGINATOR_CERT_FIELD, stream))
          != (char *)NULL)
        return (errorMessage);
    }
    else {
      if ((errorMessage = BufferStreamPuts (ISSUER_CERT_FIELD, stream))
          != (char *)NULL)
        return (errorMessage);
    }
    if ((errorMessage = WriteEOL (stream)) != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = BufferCodeAndWriteBytes
         ((unsigned char *)entry->dataptr, entry->datalen, " ", stream))
        != (char *)NULL)
      return (errorMessage);  
  }

  return ((char *)NULL);
}

#ifndef RIPEMSIG

/* This decodes messageInfo->msg_key and initializes envelopeContext
     with messageInfo->ea and messageInfo->iv and ripemInfo's private key.
   This also decodes and decrypts the messageInfo->mic, writing it to
     signature and setting signatureLen. Assume signature is at
     least MAX_SIGNATURE_LEN.
   This returns 0 or an RSAREF error code (not a char * message).
 */
static int RIPEMOpenInit
  (ripemInfo, envelopeContext, signature, signatureLen)
RIPEMInfo *ripemInfo;
R_ENVELOPE_CTX *envelopeContext;
unsigned char *signature;
unsigned int *signatureLen;
{
  int status;
  unsigned char encryptedKeyBlock[MAX_ENCRYPTED_KEY_LEN];
  unsigned int encryptedKeyBlockLen;
  RIPEMDecipherPEMFrame *frame =
    (RIPEMDecipherPEMFrame *)ripemInfo->z.decipherFrame;

  /* Make sure input values are not too big (just like in R_OpenPEMBlock).
   */
  if (frame->messageInfo.msg_key_len > MAX_PEM_ENCRYPTED_KEY_LEN)
    return (RE_KEY_ENCODING);
  
  if (frame->messageInfo.mic_len > MAX_PEM_ENCRYPTED_SIGNATURE_LEN)
    return (RE_SIGNATURE_ENCODING);

  if (R_DecodePEMBlock 
      (encryptedKeyBlock, &encryptedKeyBlockLen, frame->messageInfo.msg_key,
       frame->messageInfo.msg_key_len) != 0)
    return (RE_KEY_ENCODING);

  if ((status = R_OpenInit
       (envelopeContext, frame->messageInfo.ea, encryptedKeyBlock,
        encryptedKeyBlockLen, frame->messageInfo.iv,
        &ripemInfo->privateKey)) != 0)
    return (status);

  if ((status = MyDecryptPEMUpdateFinal
       (envelopeContext, signature, signatureLen, frame->messageInfo.mic,
        frame->messageInfo.mic_len)) != 0) {
    if (status == RE_LEN || status == RE_ENCODING)
      status = RE_SIGNATURE_ENCODING;
    else
      status = RE_KEY;
    return (status);
  }

  /* encryptedKeyBlock is not sensitive, so no need to zeroize. */
  return (0);
}

/* This is an exact copy of DecryptPEMUpdateFinal in RSAREF.
 */
static int MyDecryptPEMUpdateFinal
  (context, output, outputLen, input, inputLen)
R_ENVELOPE_CTX *context;
unsigned char *output;                          /* decoded, decrypted block */
unsigned int *outputLen;                                /* length of output */
unsigned char *input;                           /* encrypted, encoded block */
unsigned int inputLen;                                            /* length */
{
  int status;
  unsigned char encryptedPart[24];
  unsigned int i, len;
  
  do {
    /* Choose a buffer size of 24 bytes to hold the temporary decoded output
         which will be decrypted.
       Decode and decrypt as many 32-byte input blocks as possible.
     */
    *outputLen = 0;
    for (i = 0; i < inputLen/32; i++) {
      /* len is always 24 */
      if ((status = R_DecodePEMBlock
           (encryptedPart, &len, &input[32*i], 32)) != 0)
        break;

      /* Excpect no error return */
      R_OpenUpdate (context, output, &len, encryptedPart, 24);
      output += len;
      *outputLen += len;
    }
    if (status)
      break;

    /* Decode the last part */  
    if ((status = R_DecodePEMBlock
         (encryptedPart, &len, &input[32*i], inputLen - 32*i)) != 0)
      break;

    /* Decrypt the last part.
     */
    R_OpenUpdate (context, output, &len, encryptedPart, len);
    output += len;
    *outputLen += len;
    if ((status = R_OpenFinal (context, output, &len)) != 0)
      break;
    *outputLen += len;
  } while (0);

  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)&context, 0, sizeof (context));
  R_memset ((POINTER)encryptedPart, 0, sizeof (encryptedPart));

  return (status);
}

#endif /* RIPEMSIG */


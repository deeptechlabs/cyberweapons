/* This file contains the sample RSIGN application described in ripemapi.doc
 */

#include <stdio.h>
#include <string.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"

#ifdef __BORLANDC__
extern unsigned _stklen = 12192;  /* Increase stack size for Borland C */
#endif

void main ()
{
  RIPEMInfo ripemInfo;
  RIPEMDatabase ripemDatabase;
  char *errorMessage;
  unsigned char *partOut, line[256];
  unsigned int partOutLen, lineLen;

  RIPEMInfoConstructor (&ripemInfo);
  RIPEMDatabaseConstructor (&ripemDatabase);
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Initialize the database to the home directory, which must already
         exist and end in the directory seperator.
     */
    if ((errorMessage = InitRIPEMDatabase
         (&ripemDatabase, ".\\", &ripemInfo)) != (char *)NULL)
      break;

    if ((errorMessage = RIPEMLoginUser
         (&ripemInfo, "test", &ripemDatabase,
          (unsigned char *)"password", strlen ("password")))
        != (char *)NULL)
      break;

    /* Prepare for a MIC-CLEAR message. Use null values for
         encryptionAlgorithm, recipientKeys and recipientKeyCount.
     */
    if ((errorMessage = RIPEMEncipherInit
         (&ripemInfo, MODE_MIC_CLEAR, MESSAGE_FORMAT_RIPEM1, 0,
          (RecipientKeyInfo *)NULL, 0)) != (char *)NULL)
      break;

    /* Read in the test string from the stdin. Using fgets instead of
         gets means we get the ending '\n' as required by RIPEMEncipher.
     */
    puts ("Enter text to sign (one line):");
    fgets ((char *)line, sizeof (line), stdin);
    lineLen = strlen ((char *)line);

    /* Digest the message.  (In a file-based application, this would
         be called multiple times as each part of the file is read in.)
     */
    if ((errorMessage = RIPEMEncipherDigestUpdate
         (&ripemInfo, line, lineLen)) != (char *)NULL)
      break;

    /* Produce the message output and write to stdout.
       (In a file-based application, the file would first be
       rewound and this function would be called multiple times
       as each part of the file is read in.)
     */
    if ((errorMessage = RIPEMEncipherUpdate
         (&ripemInfo, &partOut, &partOutLen, line, lineLen,
          &ripemDatabase)) != (char *)NULL)
      break;
    fwrite (partOut, 1, partOutLen, stdout);

    /* Finalize and flush the final output.
     */
    if ((errorMessage = RIPEMEncipherFinal
         (&ripemInfo, &partOut, &partOutLen, &ripemDatabase))
        != (char *)NULL)
      break;
    fwrite (partOut, 1, partOutLen, stdout);
  } while (0);

  RIPEMInfoDestructor (&ripemInfo);
  RIPEMDatabaseDestructor (&ripemDatabase);

  if (errorMessage != (char *)0)
    printf ("ERROR: %s\n", errorMessage);
}

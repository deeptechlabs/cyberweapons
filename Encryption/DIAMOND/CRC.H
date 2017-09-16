/* crc.h -- header for CCITT CRC-32 function.
   This file is in the Public Domain.
*/

extern unsigned long int *Ccitt32Table;

extern int CALLTYPE BuildCRCTable(void);    
/* Allocates 1024 byte table and fills it. */

/* Make sure that the following macro is called after BuildCRCTable() but
   before crc32done(). */

#define crc32(crc, c)(((crc>>8)&0x00FFFFFFL)^(Ccitt32Table[(int)((int)crc^c)&0xFF]))

extern void CALLTYPE crc32done(void);   /* Frees up 1024 bytes of RAM. */


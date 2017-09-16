/* crc.h -- header for CRC function.
*/

extern unsigned long int *Ccitt32Table;

extern int CALLTYPE BuildCRCTable(void);
extern unsigned long CALLTYPE crc32(unsigned int count, unsigned long crc, void *buffer );
#define crc32(crc, c) (((crc >> 8) & 0x00FFFFFFL) ^ (Ccitt32Table[(int)((int) crc ^ c) & 0xFF]))
extern void CALLTYPE crc32done(void);

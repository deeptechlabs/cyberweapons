#ifndef DES_PUBLIC
#define DES_PUBLIC 1

#if (!__STDC__)
#define const
#endif

typedef unsigned char	des_u_char; /* This should be an 8-bit unsigned type */
typedef unsigned long	des_u_long; /* This should be a 32-bit unsigned type */

typedef struct {
  des_u_char	data[8];
} C_Block;

typedef struct {
  des_u_long	data[32];
} Key_schedule;

#define DES_ENCRYPT	0x0000
#define DES_DECRYPT	0x0001
#define DES_NOIPERM	0x0100
#define DES_NOFPERM	0x0200
#define DES_REVBITS	0x0400	/* For SUN compatibility */
#define DES_PAD_FF	0x0800	/* Pad with 0xff instead of 0x00
				   as required by RFC 1113 */

des_u_long	des_cbc_cksum();

extern int	des_hash_inited;
extern Key_schedule	des_hash_key1;
extern Key_schedule	des_hash_key2;
extern const C_Block	des_zero_block;
extern des_u_char des_sun_parity[];

#define DES_HASH_INIT() (des_hash_inited ? 0 : des_hash_init())

extern char	*des_crypt();

#endif

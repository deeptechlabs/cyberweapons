/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 * Additional restrictions due to national laws governing the use, import or
 * export of cryptographic software is the responsibility of the software user,
 * importer or exporter to follow.
 *
 *					     _
 *					Stig Ostholm
 *					Department of Computer Engineering
 *					Chalmers University of Technology
 */

/*
 * Mode flags to be passed in the `encrypt' parameter.
 */

#define DES_DECRYPT	0x0	/* Decryption mode. */
#define DES_ENCRYPT	0x1	/* Encryption mode. */


/*
 * DES_LSB_FIRST
 *
 *	Indicates that the package is compiled to use the least
 *	significant bit of the first character in `des_cblock' as
 *	the first bit. Default is to use the most significant bit
 *	of the first character.
 *
 *	The current version has not been tested with `DES_LSB_FIRST'.
 */
/*
#define	DES_LSB_FIRST
 */

/*
 * Number of bits in a DES block/key
 */

#define DES_BLOCK_BITS 64


/*
 * Number of bytes in a DES block/key. This assumes that 1 byte = 8 bits.
 */
#define DES_BLOCK_BYTES 8

/*
 * des_cblock
 *
 *	The base DES 64-bit data structure used both for encryption/
 *	decryption and keys.
 */

typedef unsigned char	des_cblock[DES_BLOCK_BYTES];


/*
 * des_key_schedule
 *
 *	An internal des key schedule generated form a 64-bit DES key.
 */

typedef struct	des_ks_struct {
			des_cblock	_;
		} des_key_schedule[16];

/*
 * des_return_ivec
 *
 *	DES_NO_RETURN_IVEC => The ivec argument is not modified (default).
 *	DES_RETURN_IVEC    => The ivec argument is modified to reflect
 *			      the last internal iteration.
 */

#define DES_NO_RETURN_IVEC	0x0	/* Do NOT return the last ivec value. */
#define DES_RETURN_IVEC		0x2	/* Return the last ivec value. */

extern int	des_return_ivec;	/* Default: DES_NO_RETURN_IVEC. */



/*
 * des_dea
 *
 *	The base DES encryption algorithm as described in FIPS 46 1977
 *	January 15.
 * 
 *	`des_dea' use a precomputed key schedule `schedule' to encrypt/decrypt
 *	`input' to `output' according to the setting of `encrypt'.
 *
 *	The `input' and `output' parameters must point to arrays of at
 *	least one des_cblock. The algorithm is only applied on the first
 *	block in an array.
 *
 * 	`input' and `output' may point to the same area.
 */

extern int	des_dea(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	des_key_schedule	schedule,
	int			encrypt
#endif
);


/*
 * des_key
 *
 *	The base key schedule algorithm as described in FIPS 46 1977
 *	January 15.
 *
 *	`des_key' takes a DES encryption key as specified by `key' and
 *	computes a key schedule. The result is stored in `schedule'.
 */

extern int	des_key(
#ifdef __STDC__
	des_cblock		*key,
	des_key_schedule	schedule
#endif
);



/*
 * des_ecb_encrypt
 *
 *	Calls `des_dea' with the same arguments. 
 */

extern int	des_ecb_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	des_key_schedule	schedule,
	int			encrypt
#endif
);


/*
 * des_ecb2_encrypt
 *
 *	Encryption/decryption according to the "Electronic CodeBook" method.
 *
 *	`des_ecb2_encrypt' uses a precomputed key schedule `schedule' to
 *	encrypt/decrypt `input' to `output' according to the setting of
 *	`encrypt'. `length' specifies the number of valid characters in
 *	the `input' array.
 *
 * 	If the length `input' does not equal a multiple of eight characters,
 *	zeros are appended until the resulting length is a multiple of eight
 *	characters. The caller does not have to provide any additional
 *	space in `input'.
 *
 *	The `output' array must have a sufficient length to store the result
 *	with padding included.
 *
 *	The `ivec' parameter is not used in this method.
 *
 *	`input' and `output' may point to the same area.
 */

extern int	des_ecb2_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec,
	int			encrypt
#endif
);


/*
 * des_cbc_encrypt
 *
 *	Encryption/decryption according to the "Cipher Block Chaining"
 *	method.
 *
 * 	`des_cbc_encrypt' uses a precomputed key schedule `schedule' to
 *	encrypt/decrypt `input' to `output' according to the setting of
 *	`encrypt' `length' specifies the number of valid characters in
 *	the `input' array.
 *
 *	If the length `input' does not equal a multiple of eight characters,
 *	zeros are appended until the resulting length is a multiple of eight
 *	characters. The caller does not have to provide the additional space
 *	in `input'.
 *
 *	The `output' array must have a sufficient length to store the result
 *	with padding included.
 *
 *	The `ivec' parameter contains the initial vector used by the algorithm.
 *
 *	`input' and `output' may point to the same area.
 */

extern int	des_cbc_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec,
	int			encrypt
#endif
);


/*
 * des_pcbc_encrypt
 *
 *	Encryption/decryption according to a modified "Cipher Block Chaining"
 *	used by the DES implementation in the MIT kerberos system method.
 *
 *	`des_pcbc_encrypt' uses a precomputed key schedule `schedule' to
 *	encrypt/decrypt `input' to `output' according to the setting of
 *	`encrypt'. `length' specifies the number of valid characters in
 *	the `input' array.
 *
 *	If the length `input' does not equal a multiple of eight characters,
 *	zeros are appended until the resulting length is a multiple of eight
 *	characters. The caller does not have to provide the additional space
 *	in `input'.
 *
 *	The `output' array must have a sufficient length to store the result
 *	with padding included.
 *
 *	The `ivec' parameter contains the initial vector used by the algorithm.
 *
 *	`input' and `output' may point to the same area.
 */

extern int	des_pcbc_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec,
	int			encrypt
#endif
);


/*
 * des_cfb8
 *
 *	Encryption/decryption according to the "8-bit Cipher Feedback" method.
 *
 *	`des_cfb8_encrypt' uses a precomputed key schedule `schedule' to
 *	encrypt/decrypt `input' to `output' according to the setting of
 *	`encrypt'. `length' specifies the number of valid bytes in
 *	the `input' array.
 *
 *	The `output' array must have the same or greater length than specified
 *	by `length'.
 *
 *	The `ivec' parameter contains the initial vector used by the algorithm.
 *
 *	`input' and `output' may point to the same area.
 *
 */

extern int	des_cfb8_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec,
	int			encrypt
#endif
);


/*
 * des_ofb8_encrypt
 *
 *	Encryption/decryption according to the "8-bit Output Feedback" method.
 *
 *	`des_ofb8_encrypt' uses a precomputed key schedule `schedule' to
 *	encrypt/decrypt `input' to `output' according to the setting of
 *	`encrypt'. `length' specifies the number of valid bytes in
 *	the `input' array.
 *
 *	The `output' array must have the same or greater length than
 *	specified by `length'.
 *
 *	The `ivec' parameter contains the initial vector used by the algorithm.
 *
 *	`input' and `output' may point to the same area.
 */

extern int	des_ofb8_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec,
	int			encrypt
#endif
);


/*
 * des_set_key
 *
 *	`des_set_key' uses `des_key' to generate a key schedule.
 *
 *	The routine returns -1 if the key has wrong parity, -2 if the
 *	generated key is weak, otherwise 0. If the result is non-zero no
 *	schedule has been generated.
 *
 *	The result is stored in the the argument `schedule'.
 */

extern int	des_set_key(
#ifdef __STDC__
	des_cblock		*key,
	des_key_schedule	schedule
#endif
);


/*
 * des_is_weak_key
 *
 *	`des_isweakkey' returns 1 if the key is weak, otherwise 0.
 *
 *	The key must have correct parity.
 */

extern int	des_is_weak_key(
#ifdef __STDC__
	des_cblock *key
#endif
);


/*
 * des_is_semiweak_key
 *
 *	`des_issweakkey' returns 1 if the key is semiweak, otherwise 0.
 *
 *	The key must have correct parity.
 */

extern int	des_is_semiweak_key(
#ifdef __STDC__
	des_cblock *key
#endif
);

/*
 * des_no_key_schedule
 *
 *	`des_no_key_schedule' returns a number in the range 1 .. 16
 *	indicating the number of different internal keys generated
 *	in a key schedule produced by `key'.
 *
 *	The key must have correct parity.
 */

extern int     des_no_key_schedule(
#ifdef __STDC__
	des_cblock *key
#endif
);


/*
 * des_test_key_parity
 *
 *	`des_test_key_parity' returns 1 if the key has correct parity,
 *	otherwise 0.
 */

extern int	des_test_key_parity(
#ifdef __STDC__
	des_cblock *key
#endif
);


/*
 * des_set_key_parity
 *
 *	`des_setkeyparity' adjusts the key to have odd character parity.
 *	The adjustment is made on bit 8 in all eight characters of the key.
 */

extern int    des_set_key_parity(
#ifdef __STDC__
	des_cblock *key
#endif
);


/*
 * des_random_cblock
 *
 * 	`des_random_cblock' returns a `des_cblock' generated by a random
 *	function. The seed consists of a combination of the process number,
 *	current process id and an internal counter.
 *
 *	The result is stored in `cblock'.
 */

extern int	des_random_key(
#ifdef __STDC__
	des_cblock *cblock
#endif
);


/*
 * des_random_key
 *
 * 	`des_random_key' returns a key generated by a random function.
 *	The key is a parity adjusted result from `des_random_cblock'.
 *
 *	The result is stored in `key'.
 */

extern int	des_random_key(
#ifdef __STDC__
	des_cblock *key
#endif
);


/*
 * des_string_to_key
 *
 *	This routine converts a null terminated array of characters into
 *	a des key. The result is parity adjusted.
 *
 *	The result is stored in `key'.
 */

extern int    des_string_to_key(
#ifdef __STDC__
	char		*str,
	des_cblock	key
#endif
);


/*
 * des_hex_to_cblock
 *
 *	This routine converts a null terminated array of hexadecimal
 *	characters into a `des_cblock'. If any non-hexadecimal characters
 *	are found or if the string does not contain 16 digits, the function
 *	retuns -1. If the conversion was correct, 0 is returned and the
 *	result is returned in `cblock'.
 * 
 *	The two first digits of `xstr' is the contents of `cblock[0]',
 *	the next two `cblock[1]' and so on. The conversion could be thought
 *	of as the inverse of:
 *
 *		sprintf(str "%02x%02x%02x%02x%02x%02x%02x%02x",
 *			(*cblock)[0], (*cblock)[1], (*cblock)[2], (*cblock)[3],
 *			(*cblock)[4], (*cblock)[5], (*cblock)[6], (*cblock)[7]);
 *
 */

extern int    des_hex_to_cblock(
#ifdef __STDC__
	char		*str,
	des_cblock	*cblock
#endif
);


/*
 * des_print_cblock
 *
 *	This routine prints a number of `cblock' according to the format:
 *
 *		printf("0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
 *			(*cblock)[0], (*cblock)[1], (*cblock)[2], (*cblock)[3],
 *			(*cblock)[4], (*cblock)[5], (*cblock)[6], (*cblock)[7]);
 *	
 *	The number of blocks printed is specified with `items'.
 *
 *	The default output, stdout, can be modified by setting the global
 *	variable `des_print_file' to a new value. The default format string
 *	(as show above) can be modified by setting `des_print_format' to a
 *	new value. The user must declare both these variable as external
 *	in his/hers program before they are used:
 *
 *		#include	<stdio.h>
 *
 *		extern FILE	*des_print_file;
 *		extern char	*des_print_format;
 *
 */

extern int    des_print_cblock(
#ifdef __STDC__
	des_cblock	*cblock,
	int		items
#endif
);


/*
 * des_read_password
 *
 *	This routine shows the string `prompt' on the current tty and reads
 *	a line from the current tty. If the `verify' argument is non-zero,
 *	then a second prompt requesting verification is shown. If the first
 *	and second lines do not match, then the process is tried again until
 *	both match.
 *
 *	The input echo is switched off during the operation.
 *
 *	The string (excluding any newline) is converted to a DES key by use
 *	of `des_string_to_key'.
 *
 *	`des_read_passwords' returns 0 if the operation was successful,
 *	-1 if the echo could not be switched off or -2 if the input string
 *	could not be obtained. In the last case, no key is generated.
 */

extern int	des_read_password(
#ifdef __STDC__
	des_cblock	*key,
	char		*prompt,
	int		verify
#endif
);


/*
 * des_read_hexkey
 *
 *	This routine shows the string `prompt' on the current tty and reads
 *	a line from the current tty. If the `verify' argument is non-zero,
 *	then a second prompt requesting verification is shown. If the first
 *	and second lines do not match, then the process is tried again until
 *	both match.
 *
 *	The input echo is switched off during the operation.
 *
 *	The string (excluding any newline) is converted to a DES key by use
 *	of `des_string_to_key'.
 *
 *	If the input line don't specify a 64-bit hexadecimal value, then
 *	The user is prompted again.
 *
 *	`des_read_hexkey' returns 0 if the operation was successful,
 *	-1 if the echo could not be switched off or -2 if the input string
 *	could not be obtained. In the last case, no key is generated.
 */

extern int	des_read_hexkey(
#ifdef __STDC__
	des_cblock	*key,
	char		*prompt,
	int		verify
#endif
);


/*
 * des_cbc_cksum
 *
 *	This routine makes an cryptographic checksum based on the cipher
 *	block chaining algorithm. The output is the first des_cblock pointed
 *	to by `output'. If `length' does not specify an multiple of eight
 *	bytes, the last block is null padded.
 *
 *	A 64 bit checksum is retuned in `output'. The four last byte,
 *	with the last character (*output[7]) as the most significant byte,
 *	is given as function value.
 */

unsigned long   des_cbc_cksum(
#ifdef __STDC__
	des_cblock              *input,
	des_cblock              *output,
	int                     length,
	des_key_schedule        schedule,
	des_cblock              *ivec
#endif
);


/*
 * quad_cksum
 *
 *	Implementation of the algorithm described in:
 *
 *		"Message Authentication"
 *              R. R. Jueneman, S. M. Matyas, C. H. Meyer
 *              IEEE Communications Magazine,
 *              Sept 1985 Vol 23 No 9 p 29-40
 *
 *	This implementation does not return the same value as the MIT
 *	implementation. `quad_cksum' may not be included in further
 *	releases of this encryption package.
 */

unsigned long   quad_cksum(
#ifdef __STDC__
	des_cblock      *input,
	des_cblock      *output,
	int             length,
	int             out_count,
	des_cblock      *seed
#endif
);

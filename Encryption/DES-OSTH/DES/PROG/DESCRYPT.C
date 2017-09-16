#include	"compile.h"
#include	<stdio.h>
#include	<strings.h>
#include	<des.h>

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




extern int	errno, sys_nerr;
extern char	*sys_errlist[];


typedef int	(*crypt_func_p)(
#ifdef __STDC__
			des_cblock	 *input,
			des_cblock	 *output,
			int		 length,
			des_key_schedule schedule,
			des_cblock	 *ivec,
			int		 encrypt
#endif
);

typedef int	(*action_func_p)(
#ifdef __STDC__
			des_key_schedule schedule,
			FILE		 *rfd,
			FILE		 *wfd
#endif
);

typedef int	(read_write_func)(
#ifdef __STDC__
			char *,
			unsigned,
			unsigned,
			FILE *
#endif
);

static crypt_func_p		crypt_func = NULL;
static action_func_p		action_func = NULL;
static read_write_func		*read_func = NULL, *write_func = NULL;

/*
extern read_write_func		fread, fwrite;
*/


/*
 * Encryption/decryption functions.
 *
 */

#define BUF_SIZE 8192

/*
 * This routine does the actual encryption job without padding.
 */

static int	encrypt(
#ifdef __STDC__
	des_key_schedule schedule, FILE *rfd, FILE *wfd)
#else
	schedule, rfd, wfd)
des_key_schedule	schedule;
FILE			*rfd, *wfd;
#endif
{
	register int		n;
	char			buf[BUF_SIZE];
	des_cblock 		ivec;


	/* Start with a zero init vector */
	bzero(ivec, DES_BLOCK_BYTES);

	/* Do the encryption on compleat blocks */
	while ((n = fread(buf, sizeof(*buf), BUF_SIZE, rfd)) > 0) {

		(*crypt_func)((des_cblock *) buf, (des_cblock *) buf,
			      n, schedule, (des_cblock *) ivec, DES_ENCRYPT); 
		
		VOID fwrite(buf, sizeof(*buf), n, wfd);
		if (ferror(wfd))
			return 1;
	}

	return 0;
}

/*
 * This routine does the actual decryption job without padding.
 */

static int	decrypt(
#ifdef __STDC__
	des_key_schedule schedule, FILE *rfd, FILE *wfd)
#else
	schedule, rfd, wfd)
des_key_schedule	schedule;
FILE			*rfd, *wfd;
#endif
{
	register int		n;
	char			buf[BUF_SIZE];
	des_cblock 		ivec;


	/* Start with a zero init vector */
	bzero(ivec, DES_BLOCK_BYTES);

	/* Do the encryption on compleat blocks */
	while ((n = fread(buf, sizeof(*buf), BUF_SIZE, rfd)) > 0) {

		(*crypt_func)((des_cblock *) buf, (des_cblock *) buf,
			      n, schedule, (des_cblock *) ivec, DES_DECRYPT); 
		
		VOID fwrite(buf, sizeof(*buf), n, wfd);
		if (ferror(wfd))
			return 1;
	}

	return 0;
}

/*
 * Bitmask for bits contaning padding information
 */

/* 0x00001000 - 0x00000001 -> 0x00000111 (8 - 1 -> 7) */
#define PAD_INFO_BITS (DES_BLOCK_BYTES - 1)

static int	encrypt_padding(
#ifdef __STDC__
	des_key_schedule schedule, FILE *rfd, FILE *wfd)
#else
	schedule, rfd, wfd)
des_key_schedule	schedule;
FILE			*rfd, *wfd;
#endif
{
	register int		nr, nw;
	char			buf[BUF_SIZE + DES_BLOCK_BYTES];
	des_cblock 		ivec;


	/* Start with a zero init vector */
	bzero(ivec, DES_BLOCK_BYTES);

	/* Do the encryption on compleat blocks */
	while ((nr = fread(buf, sizeof(*buf), BUF_SIZE, rfd)) == BUF_SIZE) {

		(*crypt_func)((des_cblock *) buf, (des_cblock *) buf,
			      BUF_SIZE, schedule, (des_cblock *) ivec,
			      DES_ENCRYPT); 
		
		VOID (*write_func)(buf, sizeof(*buf), BUF_SIZE, wfd);
		if (ferror(wfd))
			return 1;
	}

	/* The last section handles padding to ensure that the	*/
	/* encryption is made on compleat eight byte block(s).	*/
	/* The last block will always contain 0 .. 7 bytes of	*/
	/* data, and the last byte contains a number indicating	*/
	/* how may bytes (0 .. 7) that are use for actual data.	*/
	/* Any remaining bits between data bits and the last is */
	/* padded with random bits.				*/
	VOID des_random_cblock((des_cblock *) &buf[nr]);
	nw = ((nr + DES_BLOCK_BYTES) / DES_BLOCK_BYTES) * DES_BLOCK_BYTES;
	buf[nw - 1] = (buf[nw - 1] & ~ PAD_INFO_BITS) | (nr & PAD_INFO_BITS);

	(*crypt_func)((des_cblock *) buf, (des_cblock *) buf, nw,
		      schedule, (des_cblock *) ivec, DES_ENCRYPT); 

	VOID (*write_func)(buf, sizeof(*buf), nw, wfd);

	return 0;
}

/*
 * This routine does the actual decryption job with padding.
 */

static int	decrypt_padding(
#ifdef __STDC__
	des_key_schedule schedule, FILE *rfd, FILE *wfd)
#else
	schedule, rfd, wfd)
des_key_schedule	schedule;
FILE			*rfd, *wfd;
#endif
{
	register int	nr, nw, corrupt;
	char		ibuf[BUF_SIZE], obuf[BUF_SIZE];
	des_cblock 	ivec;


	/* Start with a zero init vector. */
	bzero(ivec, DES_BLOCK_BYTES);

	/* Do the decryption on the source file */

	/* Read the first block, return with error if the file has 0 size. */
	if (!(nw = nr = (*read_func)(ibuf, sizeof(*ibuf), BUF_SIZE, rfd)))
		return 1;

	/* Decrypt the the current input buffer into the output buffer */
	VOID (*crypt_func)((des_cblock *) ibuf, (des_cblock *) obuf, nr,
   			   schedule, (des_cblock *) ivec, DES_DECRYPT); 

	/* Read until end of file is found */
	while ((nr = (*read_func)(ibuf, sizeof(*ibuf), BUF_SIZE, rfd)) > 0) {

		/* Write the decrypted contentse of the previous buffer. */
		VOID fwrite(obuf, sizeof(*obuf), nw, wfd);
		if (ferror(wfd))
			return 0;

		nw = nr;

		/* Decrypt the the current input buffer into the output	*/
		/* buffer.						*/
		VOID (*crypt_func)((des_cblock *) ibuf, (des_cblock *) obuf, nr,
	   			   schedule, (des_cblock *) ivec, DES_DECRYPT); 

	}

	/* The last buffer contains padding information that has to be	*/
	/* removed. The buffer mist contain at least on block		*/
	corrupt = 0;
	if (nw >= DES_BLOCK_BYTES) {
		/* The last block must contain an multiple of blocks. */
		corrupt = nw % DES_BLOCK_BYTES;
		/* The last byte in the block contains padding infomration. */
		/* Remove the padding bytes and the padding info.	    */
		nw -= DES_BLOCK_BYTES - (obuf[nw - 1] & PAD_INFO_BITS);
	} else
		corrupt = 1;

	/* Write the last output buffer with padding information removed. */
	VOID fwrite(obuf, sizeof(*obuf), nw, wfd);

	return corrupt;
}

static int	checksum(
#ifdef __STDC__
	des_key_schedule schedule, FILE *rfd, FILE *wfd)
#else
	schedule, rfd, wfd)
des_key_schedule	schedule;
FILE			*rfd, *wfd;
#endif
{
	register int		nr;
	char			buf[BUF_SIZE + DES_BLOCK_BYTES];
	des_cblock 		ivec, sum;


	/* Start with a zero init vector */
	bzero(ivec, DES_BLOCK_BYTES);

	while ((nr = fread(buf, sizeof(*buf), BUF_SIZE, rfd)) > 0)
		VOID des_cbc_cksum((des_cblock *) buf, (des_cblock *) sum,
				   nr, schedule, (des_cblock *) ivec);

	VOID (*write_func)((char *) sum, sizeof(*sum), sizeof(sum), wfd);

	return 0;
}

/*
 * ASCII input/output functions
 */

int	ascii_read(
#ifdef __STDC__
	char *ptr, unsigned ptr_size, unsigned items, FILE *fd)
#else
	ptr, ptr_size, items, fd)
char		*ptr;
unsigned	ptr_size;
unsigned	items;
FILE		*fd;
#endif
{
	register int	n, l, r;
	char		buf[BUF_SIZE];

	
	n = ptr_size * items;
	r = 0;
	while (n >= DES_BLOCK_BYTES) {
		if (fgets(buf, BUF_SIZE, fd) == NULL)
			break;
		l = strlen(buf) - 1;
		if (buf[l] != '\n')
			continue;
		buf[l] = '\0';
		if (des_hex_to_cblock(buf, (des_cblock *) ptr))
			continue;
		r += DES_BLOCK_BYTES;
		ptr += DES_BLOCK_BYTES;
		n -= DES_BLOCK_BYTES;
	}
	return r / ptr_size;
}

int	ascii_write(
#ifdef __STDC__
	char *ptr, unsigned ptr_size, unsigned items, FILE *fd)
#else
	ptr, ptr_size, items, fd)
char		*ptr;
unsigned	ptr_size;
unsigned	items;
FILE		*fd;
#endif
{
	register int	n;
	des_cblock	*b;
	FILE		*old_fd;
	extern FILE	*des_print_file; 

	
	old_fd = des_print_file;
	des_print_file = fd;
	b = (des_cblock *) ptr;
	n = ptr_size * items;
	n = des_print_cblock(b, n / DES_BLOCK_BYTES);
	des_print_file = old_fd;
	return n * DES_BLOCK_BYTES;
}


main(argc, argv)
int	argc;
char	*argv[];
{
	register int		n, i, j, key_len, cr;
	register int		ascii_io, use_hex, use_padding;
	register char		*prog, *rfname, *wfname, *strkey;
	FILE			*rfd, *wfd;
	des_key_schedule	schedule;
	des_cblock		key;


	/* The program name. */
	prog = ((prog = rindex(*argv, '/')) == NULL) ? *argv : 1 + prog;

	/* Set initial values. */
	use_padding = use_hex = ascii_io = cr = key_len = 0;
	rfd = wfd = NULL;
	rfname = wfname = strkey = NULL;

	/* Get the kommand line arguments. */
	for (i = 1; i < argc; i = n) {
		switch (*argv[i]) {
		case '\0':
			goto usage;
		case '-':
			if (rfname != NULL || !argv[i][1])
				goto usage;
			n = i + 1;
			break;
		default:
			if (rfname == NULL)
				/* The name of the source file */
				rfname = argv[i];
			else if (wfname == NULL)
				/* The name of the destination file */
				wfname = argv[i];
			else
				goto usage;
			n = i + 1;
			continue;
		} 
		for (j = 1; argv[i][j]; j++)
			switch (argv[i][j]) {
			case 'e':
				if (action_func != NULL)
					goto usage;
				action_func = (action_func_p) encrypt;
				continue;
			case 'd':
				if (action_func != NULL)
					goto usage;
				action_func = (action_func_p) decrypt;
				continue;
			case 'c':
				if (action_func != NULL)
					goto usage;
				action_func = (action_func_p) checksum;
				continue;
			case 'a':
				if (ascii_io)
					goto usage;
				ascii_io = 1;
				/* Ascii input/output requires padding */
				use_padding = 1;
				continue;
			case 'h':
				if (use_hex)
					goto usage;
				use_hex = 1;
				continue;
			case 'k':
				if (strkey != NULL || n >= argc)
					goto usage;
				key_len = strlen(argv[n]);
				strkey = (char *) malloc(key_len + 1);
				if (strkey == NULL)
					goto memalloc;
				VOID strcpy(strkey, argv[n]);
				/* Destroy the argument vector key. */
				bzero(argv[n++], key_len);
				continue;
			case 'C':
				if (crypt_func != NULL)
					goto usage;
				crypt_func = (crypt_func_p) des_cbc_encrypt;
				use_padding = 1;
				continue;
			case 'P':
				if (crypt_func != NULL)
					goto usage;
				crypt_func = (crypt_func_p) des_pcbc_encrypt;
				use_padding = 1;
				continue;
			case 'E':
				if (crypt_func != NULL)
					goto usage;
				crypt_func = (crypt_func_p) des_ecb2_encrypt;
				use_padding = 1;
				continue;
			case 'F':
				if (crypt_func != NULL)
					goto usage;
				crypt_func = (crypt_func_p) des_cfb8_encrypt;
				continue;
			case 'O':
				if (crypt_func != NULL)
					goto usage;
				crypt_func = (crypt_func_p) des_ofb8_encrypt;
				continue;
			default:
				goto usage;
			}
	}
	

	/* Is the encryption/decryption mode set */
	if (action_func == NULL)
		goto usage;
	if (crypt_func == NULL) {
		/* Default encryption/decryption function. */
		crypt_func = (crypt_func_p) des_cbc_encrypt;
		/* This method requires padding */
		use_padding = 1;
	}
	if (use_padding) {
		/* Padding to a multiple of des_cblock is required. */
		if (action_func == encrypt) 
			action_func = encrypt_padding;
		else
			action_func = decrypt_padding;
	}
	if (ascii_io) {
		read_func = (read_write_func *) ascii_read;
		write_func = (read_write_func *) ascii_write;
	} else {
		read_func = (read_write_func *) fread;
		write_func = (read_write_func *) fwrite;
	}

	/* If there was no key set on the argument line, fetch one from	*/
	/* the tty.							*/
	if (strkey != NULL) {
		if (use_hex) {
			if (des_hex_to_cblock(strkey, (des_cblock *) key))
				goto badhex;
			VOID des_set_key_parity((des_cblock *) key);
		} else 
			VOID des_string_to_key(strkey, key);
		/* Destroy the key. */
		free(strkey);
	} else {
		if (use_hex)
			n = des_read_hexkey((des_cblock *) key, "Hexkey: ", 1);
		else
			n = des_read_password((des_cblock *) key, "Key: ", 1);
		if (n == -2)
			goto nokey;
	}

	/* Make a key schedule */
	if (des_set_key((des_cblock *) key, schedule) < 0)
		goto weakkey;

	/* Open the file(s) */
	if (rfname != NULL) {
		/* Open the source file. */
		if ((rfd = fopen(rfname , "r")) == NULL)
			goto rfilerr;
		clearerr(rfd);
	} else {
		/* No source file, use stdin. */
		rfd = stdin;
		rfname = "<stdin>";
	}
	if (wfname != NULL) {
		/* Open the destination file. */
		if ((wfd = fopen(wfname , "w")) == NULL)
			goto wfilerr;
		clearerr(wfd);
	} else {
		/* No destination file, use stdout. */
		wfd = stdout;
		wfname = "<stdout>";
	}

	/* Encrypt/decrypt the file */
	des_return_ivec = DES_RETURN_IVEC;
	cr = (*action_func)(schedule, rfd, wfd);

	/* Was there any error during read or write ? */
	if (ferror(rfd))
		goto rfilerr;
	if (ferror(wfd))
		goto wfilerr;

	/* No check is neccessary here */
	VOID fclose(rfd);
	rfd = NULL;

	/* This check is neccessary when dealing with AFS. */
	if (fclose(wfd) == EOF) {
		wfd = NULL;
		goto wfilerr;
	} else
		wfd = NULL;

	/* Was the encrypted file corrupt ? */
	if (cr)
		goto corrupt;

	exit(0);

	/* Error handling section */
usage:
	fprintf(stderr, "Usage: %s -e|-d|-c [-h] [-k strkey] [-C|-P|-E|-F|-O] [-a] [-t] [infile [outfile]]\n", prog);
	exit(1);
memalloc:
	if (0 <= errno && errno < sys_nerr)
		fprintf(stderr, "%s: Could not allocate memory (%s)\n",
			prog, sys_errlist[errno]);
	else
		fprintf(stderr, "%s: Could not allocate memory (errno=%d)\n",
			prog, errno);
	exit(1);
rfilerr:
	if (rfd)
		VOID fclose(rfd);
	if (wfd)
		VOID fclose(wfd);
	if (0 <= errno && errno < sys_nerr)
		fprintf(stderr, "%s: Open/read error on \"%s\" (%s)\n",
			prog, rfname, sys_errlist[errno]);
	else
		fprintf(stderr, "%s: Open/read error on \"%s\" (errno=%d)\n",
			prog, rfname, errno);
	exit(1);
wfilerr:
	if (rfd)
		VOID fclose(rfd);
	if (wfd)
		VOID fclose(wfd);
	if (0 <= errno && errno < sys_nerr)
		fprintf(stderr, "%s: Open/write error on \"%s\" (%s)\n",
			prog, wfname, sys_errlist[errno]);
	else
		fprintf(stderr, "%s: Open/write error on \"%s\" (errno=%d)\n",
			prog, wfname, errno);
	exit(1);
weakkey:
	fprintf(stderr, "%s: The keys generated is weak\n", prog);
	exit(1);
badhex:
	fprintf(stderr, "%s: The hexkey must be a 64 bit hex number.\n", prog);
	exit(1);
nokey:
	fprintf(stderr, "%s: Can not obtain key\n", prog);
	exit(1);
corrupt:
	if (rfd)
		VOID fclose(rfd);
	if (wfd)
		VOID fclose(wfd);
	fprintf(stderr, "%s: Encrypted file \"%s\" is corrupt\n", prog, rfname);
	exit(1);
}

/*
 * Specifications of inter-module dependencies.
 *
 * Robert W. Baldwin, December 1984.
 */


/* General Information. */

/* A pvec is an 'string' of integers that represent plaintext
 *    characters.  The string is terminated by a -1.
 * A pbuf is a fixed length array of integers that represent plaintext
 *    characters.  A value of -1 means that the characters is unknown.
 * A cbuf is a fixed length array of bytes that represent ciphertext chars.
 * A perm is a mapping from shifted ciphertext characters to shifted
 *    plaintext characters.  Each character is shifted (incremented) by
 *    its offset in the block of 256 characters that contain it.
 * A gsi is a data structure about a guess that includes information
 *    on the characters that are assumed to be right.
 * An eci is a data structure that descibes a block of cipher and
 *    plain text.
 * A string is a null terminated vector of bytes.
 */


extern	twindow	banner;
extern	twindow	webster;
extern	twindow	dblabel;
extern	gwindow	dbstore;
extern	twindow	gblabel;
extern	gwindow	gbstore;
extern	twindow	user;

extern	gwindow	*ibanner();
extern	gwindow	*iwebster();
extern	gwindow	*idblabel();
extern	gwindow	*idbstore();
extern	gwindow	*igblabel();
extern	gwindow	*igbstore();
extern	gwindow	*iuser();

extern	char	*savestr();
extern	int	substrp(/* big, little */);
extern	int	read_slashed(/* *string */);

extern	char *(quitcmd(/* arg-string */));
extern	char *(lpbguess(/* arg-string */));
extern	char *(atrguess(/* arg-string */));
extern	char *(kntguess(/* arg-string */));
extern	char *(ecbguess(/* arg-string */));
extern	char *(pwdguess(/* arg-string */));
extern	char *(permsave(/* arg-string */));
extern	char *(permload(/* arg-string */));
extern	char *(webmatch(/* arg-string */));
extern	char *(clearzee(/* arg-string */));
extern	char *(pgate(/* arg-string */));

extern	char *(cmddo(/* cmdtab, string */));
extern	char *(cmdcomplete(/* cmdtab, string */));
extern	gblset(/* w, string */);
extern	gbsswitch(/* w, private, keytable, firsttime, lasttime, draw */);
extern	gbsclear(/* w */);
extern	hstadd(/* w, string */);
extern	usrstatus(/* w, string */);
extern	usrhelp(/* w, string */);
extern	dblbnum(/* w, int */);
extern	int	dbsmerge(/* w, perm */);
extern	dbssetblk(/* w, int */);
extern	int	dbsgetblk(/* w */);
extern	dbstrypq(/* ecbi, pque_hdr, pos */);

extern	float	score(/* pbuf */);
extern	float	gsi_1score(/* gsi */);		/* Uses 1st order stats. */
extern	float	gsi_2score(/* gsi */);		/* Uses 2nd order stats. */
extern	float	var_1score(/* pvec */);		/* Uses first order stats. */
extern	float	prob_1score(/* pvec */);	/* Uses first order stats. */
extern	float	pvec_1score(/* pvec */);	/* Uses first order stats. */
extern		load_1stats();			/* Loads first order stats. */
extern		print_1stats();

extern	int	decode(/* cbuf, pbuf, perm */); /* FALSE if has bad chars. */
/* Return -1 if	bad chars, otherwise # of chars added to pvec. */
extern	int	decode_wire(/* eci, x, y, pvec */);
/* Returns -1 if bad chars, otherwise # of chars added to pvec. */
extern	int	decode_class(/* eci, firstpos, firstplain, pvec */);
/* Returns number of wires added to permvec assuming that plaintext
 * str occurs at pos.  Fills in permvec.  Returns -1 if conflict. */
extern	int	perm_from_string(/* eci, str, pos, permvec */);
/* Fills in pvec with the plaintext characters deduced
 * from the wires in permvec that are not in the positions
 * ranging from butfirst to butlast.  Returns -1 if any
 * non-ascii chars are deduced, else count of chars. */
extern	int	permvec2pvec(/* eci, permvec, pvec, butfirst, butlast */);
extern		permvec_copy(/* from, to, maxnum */);
extern		pvec_copy(/* from, to, maxnum */);
extern		print_pvec(/* stream, pvec */);
extern		char2buf(/* cbuf, pbuf, length */);	/* Fills in pbuf. */
extern		buf2char(/* cbuf, pbuf, length, nonechar */); /* Fill cbuf. */
extern		str2pvec(/* string, pvec */);		/* Fills in pvec. */
extern		pvec2str(/* string, pvec */);		/* Fills in string. */

extern	int	fillcbuf(/* blocknum, *cbuf */);   /* Ret TRUE if sucessful. */
extern	int	*refperm(/* blocknum */);	   /* Ret NULL if fails. */
extern	copyperm(/* src, dst */);
extern	readperm(/* fd, permbuffer */);	/* Gets chars from fd to fill perm. */
extern	writeperm(/* fd, permbuffer */);	   /* Writes perm to file. */
extern	multperm(/* left, right, result = (left)(right) */);
extern	expperm(/* src, dst, k */);		   /* dst = src ** k. */
extern	int	permcount(/* perm */);		   /* Return # values != -1. */
extern	int	permwcount(/* perm */);		   /* Return # of wires. */

extern		approx_init();		/* Call before fexp or isqrt. */
extern	float	fexp(/* float */);	/* Fast exp func. */
extern	float	isqrt[];		/* Sqrts of integers < BLOCKSIZE */


/* Globals State */
extern	char	*cipherfile;		/* Ciphertext file name. */
extern	char	*permfile;		/* Permutation save file name. */
extern	char	*letterstats;		/* Single letter stat file name. */
extern	char	*bigramstats;		/* Letter pair statistics file name. */
extern	char	*trigramstats;		/* Trigram statistics file name. */
extern	int	permchgflg;	        /* TRUE if perms chged since save. */
extern	char	statmsg[];		/* Buffer to build status messages. */


/* Extensions to C */
#ifndef reg
#define	reg		register
#endif
#define	abs(x)	(((x) > 0) ? x : (0 - x))


/* Macros */
#define graphic(c)	(c & SYMBOL)
#define notascii(c)	(c>127)
#define printable(c)	((32 <= c) && (c <= 126))
#define lletter(c)	(('a'<= (c)) && ((c) <= 'z'))
#define uletter(c)	(('A'<= (c)) && ((c) <= 'Z'))
#define isspace(c)	( ((c) == ' ') || ((c) == '\t') || ((c) == '\n') )
#define isletter(c)	(lletter(c) || uletter(c))
#define tolower(c)	( uletter(c) ? ((c) - 'A' + 'a') : (c) )


/* Constants */
#define	BLOCKSIZE	256	/* Number of chars in a cipher block. */
#define MODMASK		0377	/* Arithmetic mod 256. */
#define	CHARMASK	0177	/* ASCII char mask. */
#define	MAXCHAR		127	/* Highest ASCII value. */
#define MXBIINDEX	40	/* Num different chars in a bigram. */
#define LINELEN		64	/* Number of characters per line. */
#define	NLINES		4	/* Number of line pairs. */
#define	NONE		(-1)	/* No info on something. */
#define	ERROR		(-1)	/* Procedure can't meet normal case specs. */
#define	EOL		(-37)	/* A hack used by read_char() */
#define	PI		(3.1415926)
#define	NPERMS		15	/* Max number of blocks in a file. */

#ifndef	TRUE
#define	TRUE		1	/* The whole truth. */
#endif
#ifndef	FALSE
#define	FALSE		0	/* Lies, falsehoods, etc. */
#endif
#ifndef NULL
#define	NULL		0	/* A zero by any other name ... */
#endif

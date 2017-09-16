/*
 * Definitions for terminals (symbols, graphics, keystroke, commands).
 *
 * Author: Bob Baldwin, October 1986.
 */


/* Names of shell variables for keystroke map and symbol map.
 */
#define	GRAPHICSVAR	"GRAPHICSMAP"
#define	KEYMAPVAR	"KEYMAP"


/* Screen control strings from termcap entry.
 */
extern	char	*term_is;		/* Terminal initializaion string. */
extern	char	*erase_eol;		/* Erase to end of line. */
extern	char	*erase_eos;		/* Erase to end of screen. */
extern	char	*erase_scr;		/* Erase whole screen. */
extern	char	*cm;			/* Cursor motion. */
extern	char	*start_alt;		/* Start graphics mode. */
extern	char	*end_alt;		/* End graphics mode. */
extern	char	*start_so;		/* Start standout mode. */
extern	char	*end_so;		/* End standout mode. */
extern	char	*start_kp;		/* Start send keypad escapes. */
extern	char	*end_kp;		/* End send keypad escapes. */

/* Keymap strings from termcap file.
 */
extern	char	*term_f1;		/* The f1 key. */
extern	char	*term_f2;		/* The f2 key. */
extern	char	*term_f3;		/* The f3 key. */
extern	char	*term_f4;		/* The f4 key. */
extern	char	*term_up;		/* Up arrow. */
extern	char	*term_down;		/* Down arrow. */
extern	char	*term_left;		/* Left arrow. */
extern	char	*term_right;		/* Right arrow. */


/* Flag values
 */
#define	CHARM		0377		/* Mask for 8 bit chars. */
#define SYMBOL		128		/* OR'ed with symbol codes. */
#define	SYMBOLM		(SYMBOL - 1)	/* Mask for symbol codes. */


/* Symbol codes.
 * These can be used as array indices if the SYMBOL bit is stripped.
 */
#define	STAB		(0 | SYMBOL)	/* Tab character. */
#define	SNOTASCII	(1 | SYMBOL)	/* Byte with high bit set. */
#define	SLINEFEED	(2 | SYMBOL)	/* Linefeed character. */
#define	SCARETURN	(3 | SYMBOL)	/* Return character. */
#define	SFORMFEED	(4 | SYMBOL)	/* Formfeed character. */
#define	SCONTCODE	(5 | SYMBOL)	/* Other control characters. */
#define	SUNKNOWN	(6 | SYMBOL)	/* Character decryption unknown. */
#define	SUNDERLINE	(7 | SYMBOL)	/* Pseudo underline symbol, it */
    					/* highlights char on prev line. */
#define	SVERTBAR	(8 | SYMBOL)	/* Vertical bar. */
#define	SHORZBAR	(9 | SYMBOL)	/* Horizontal bar. */
#define	SLLCORNER	(10 | SYMBOL)	/* Lower-left corner. */
#define	NSYMC		 11		/* Number of symbol codes. */


/* Default graphics settings, in the format of the shell variable.
 * Extra spaces, tabs and colons are for testing.
 * Entries are separated by spaces, tabs, or colons, and
 * terminated by colon or NULL.
 */
#define	VARSEP		"\t \n:"
#define	VARTERM		":"
#define	GVARMODES	"NGS"		/* From s_mode values */
#define	DGRAPHICS	"tb=\\St:na=\\SX: lf=\\Sn:cr=\\Sr:	:\
 			 ff=\\Sf:cc=\\SC:uk=\\S :::ul=\\N^:\
 			 hb=\\N-:vb=\\N|:ll=\\N`"


/* Structure of symbol to graphics table.
 * The s_seq strings are allocated from the heap during init.
 * The table graphtab is indexed by the symbol code.
 */
#define	SMNORMAL	'N'	/* Values for s_mode. */
#define	SMGRAPHIC	'G'
#define	SMSTANDOUT	'S'
#define	symgraph	struct symgraphx
symgraph	{
	int	s_mode;			/* Symbol display mode. */
	char	*s_seq;			/* Chars to send in that mode. */
};


/* Command codes.
 * These are not intended to be used as array indices.
 * Note problem with CNONE.
 */
#define	CMDSHIFT	8		/* Commands in high byte. */
#define	CMDMASK		0377		/* Mask to get cmd code. */
#define	CNONE		0		/* Not a command. */
#define	CGO_UP		1		/* Sames as jogcursor() arg. */
#define	CGO_DOWN	2
#define	CGO_LEFT	3
#define CGO_RIGHT	4
#define	CREFRESH	5		/* Refresh screen. */
#define	CUNDO		6		/* Undo guess. */
#define	CCLRLINE	7		/* Clear whole line. */
#define	CWRDSRCH	8		/* Search for word. */
#define	CDELF		9		/* Delete forward. */
#define	CDELB		10		/* Delete backward. */
#define	CPREVBLOCK	11		/* Goto previous block. */
#define CNEXTBLOCK	12		/* Goto next block. */
#define	CNEXTGUESS	12		/* Next guess. */
#define CNEXTARG	12		/* Goto next arg in template. */
#define	CACCEPT		13		/* Accept guess. */
#define	CEXECUTE	14		/* Execute a command. */
#define	CRETURN		14		/* Insert a return char. */
#define	CINSERT		15		/* Insert the arg char. */
#define	CTRYALL		16		/* Try all chars here. */
#define	CJUMPCMD	17		/* Jump to cmd line. */


/* See cmdnames[] for a list of the field labels in the default keymap.
 */
#define	DKEYMAP		"ta=\024:up=\020:do=\016:le=\002:ri=\006:\
 			 re=\014:un=\007:cl=\025:ws=\027:\
 			 df=\\004:db=\177:jc=\030:ex=\\n:\
 			 pr=\022:ne=\023:ac=\001"


/* Structure of key command table.
 * The c_seq strings are allocated from the heap during init.
 */
#define	keycmd	struct keycmdx
keycmd	{
	int	c_code;			/* Command code. */
	char	*c_seq;			/* Chars in keystroke. */
};


/* Structure for parsing shell variables in a format like termcap.
 * The last entry in a table of these has label == NULL.
 */
#define	labelv	struct	labelvx
labelv	{
	char	*label;		/* Label string. */
	int	value;		/* Arbitrary value for label. */
};


#define	DIGITS	"0123456789"

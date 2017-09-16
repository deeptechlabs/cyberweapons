/*
 * Constants that define the layout of the screen.
 *
 * Robert W. Baldwin, December 1984.
 */



/* Parameter for the screen layout. */

#define	WINDNUM		7				/* Number of windows at top level. */

#define	BANLM		21				/* Left margin of banner text. */
#define	BANTEXT		"Crypt Breaker's Workbench"

#define	DBLROW		2				/* Starting row of label. */
#define	DBLCOL		9				/* Column where block number starts. */
#define	DBSROW		(DBLROW+1)		/* Decryption Block. */
#define	DBWIDTH		65				/* Decrypted block. */
#define	DBHEIGHT	11				/* Decrytped block, not incl label. */
#define	DBLTEXT		"Block -"		/* Label for decrypted block. */

#define GBLROW		(DBSROW+DBHEIGHT)	/* Guess block label row. */
#define	GBSROW		(GBLROW+1)		/* Guess block storage row. */
#define	GBWIDTH		DBWIDTH			/* Width of same. */
#define GBHEIGHT	6				/* Height of same. */
#define	GBLTEXT		"Guess Window"	/* Label for guess block. */

#define	WEBROW		DBLROW			/* Starting row of history */
#define	WEBCOL		(DBWIDTH+1)		/* Starting column */
#define	WEBWIDTH	(MAXWIDTH-DBWIDTH)		/* Decision history. */
#define	WEBHEIGHT	(DBHEIGHT+GBHEIGHT+2)	/* Includes a title line. */

#define USRROW		(GBSROW+GBHEIGHT)	/* User I/O area. */
#define USRSCOL		10				/* Starting column of status msgs. */
#define USRHEIGHT	(MAXHEIGHT-(GBHEIGHT+1)-(DBHEIGHT+1)-(1))
/* total - guess block and title - decrypt block and title - banner */
#define USRWIDTH	MAXWIDTH		/* Width of I/O window. */

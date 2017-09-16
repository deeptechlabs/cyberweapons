/* Graphical cycler for NSEA (and other encryption algorithms).  Written by
   Robert Ames (mirage1@gpu.utcs.utoronto.ca), later mangled by Peter Gutmann.

   Note that this code requires the Borland Graphics Interface files
   EGAVGA.BGI and TRIP.CHR, and is somewhat hardwired towards a VGA system */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <graphics.h>
#include "nsea.h"

/* The following is normally defined in conio.h */

int getch( void );

#define ESC 0x1b
int MaxX, MaxY;
unsigned long iter = 0L;

void get8(BYTE *);
void get16(BYTE *);
void put8(BYTE *);
void put16(BYTE *);
void Initialize(void);
void Pause(void);
void MainWindow(char *header);
void StatusLine(char *msg);
void changetextstyle(int font, int direction, int charsize);

/****************************************************************************
*																			*
*						Graphical NSEA Cycle Display						*
*																			*
****************************************************************************/

/* Draw a block of NSEA-encrypted data */

static void drawData( const BYTE *data, const int xPos, const int yPos )
	{
	int i;
	BYTE far *scrnPtr = MK_FP( 0xA000, ( yPos * 80 ) + ( xPos >> 3 ) );

	for( i = 0; i < BLOCKSIZE; i++ )
		*scrnPtr++ = data[ i ];

#if 0
	/* The following code is a fraction faster but mem-model specific */
	memcpy( scrnPtr, data, BLOCKSIZE );

	/* The following code is portable but infinitely slower than using direct
	   screen writes.  Note that using setlinestyle()+line() isn't possible
	   since the routines don't seem to handle the high bit properly */
	for( i = 0; i < BLOCKSIZE; i++ )
		{
		mask = 0x80;
		for( j = 0; j < 8; j++ )
			{
			putpixel( xPos + ( i * 8 ) + j, yPos, \
					( data[ i ] & mask ) ? WHITE : BLACK );
			mask >>= 1;
			}
		}
#endif /* 0 */
	}

void main( int argc, char *argv[] )
{
	int i;
	BYTE key[8], work[BLOCKSIZE];
	BOOLEAN useDefault = FALSE;

	initNSEA();

	/* Check args */
	if( argc > 1 )
		{
		if( !strcmp( argv[ 1 ], "-d" ) )
			useDefault = TRUE;
		else
			{
			puts( "Usage: NGCYCLE {-d}" );
			puts( "                -d = Use default settings" );
			exit( ERROR );
			}
		}

	/* Get key from user */
	if( !useDefault )
		{
		*key = '\0';
		printf( "Enter key (8 hex bytes): " );
		get8( key );
		}
	else
		memset( key, 0, 8 );
	printf( "Setting key: " );
	put8( key );
	puts( "\n" );

	/* Get initial data value from user */
	if( !useDefault )
		{
		printf( "Enter starting value (16 hex bytes): " );
		get16( work );
		}
	else
		memset( work, 0, 16 );
	printf( "Starting value: " );
	put16( work );
	puts( "\n" );

	initSBoxes( key, 8, DEFAULT_SALT );
	initIV( DEFAULT_SALT );
    Initialize();		/* Set system into Graphics mode     */
	setcolor( LIGHTCYAN );
	MainWindow( "NSEA Cycler" );
	StatusLine( "Press any key or ESC to exit" );
/*	StatusLine( "Press any key to continue or any other key to exit" ); */

	/* The following code draws 4 columns of 410 iterations each of the
	   NSEA core encryption routine */
	while( TRUE )
		{
		for( i = 40; i < 450; i ++ )
			{
			encrypt( work, work );
			drawData( work, 50, i );
			iter++;
			}
		for( i = 40; i < 450; i ++ )
			{
			encrypt( work, work );
			drawData( work, 185, i );
			iter++;
			}
		for( i = 40; i < 450; i ++ )
			{
			encrypt( work, work );
			drawData( work, 320, i );
			iter++;
			}
		for( i = 40; i < 450; i ++ )
			{
			encrypt( work, work );
			drawData( work, 460, i );
			iter++;
			}

		Pause();
		}
	}

void
get8(BYTE *cp)
{
    int i, t;

    for (i = 0; i < 8; i++)
    {
	scanf("%2x", &t);
	*cp++ = t;
    }
}

void
put8(BYTE *cp)
{
    int i;

    for (i = 0; i < 8; i++)
    {
	printf("%02X ", *cp++);
    }
}

void
get16(BYTE *cp)
{
    int i, t;

    for (i = 0; i < 16; i++)
    {
	scanf("%2x", &t);
	*cp++ = t;
    }
}

void
put16(BYTE *cp)
{
    int i;

    for (i = 0; i < 16; i++)
    {
	printf("%02X ", *cp++);
    }
}

/* INITIALIZE: Initializes the graphics system and reports   */
/* any errors which occured.                     */

void
Initialize(void)
{
	int GraphDriver, GraphMode, ErrorCode;

	GraphDriver = DETECT;	/* Request auto-detection    */
    initgraph(&GraphDriver, &GraphMode, "");
    ErrorCode = graphresult();	/* Read result of initialization */
    if (ErrorCode != grOk)
    {				/* Error occured during init     */
	printf(" Graphics System Error: %s\n", grapherrormsg(ErrorCode));
	exit(1);
    }
	if( GraphDriver != VGA )
		{
		puts( "This program needs a VGA to run" );
		exit( ERROR );
		}

	/* Get screen size - should be 640x480 anyway */
	MaxX = getmaxx();
	MaxY = getmaxy();

	/* Set various settings used throughout the code */
	settextjustify( CENTER_TEXT, TOP_TEXT );
	changetextstyle( 1, HORIZ_DIR, 1 );	/* 1 = triplex, 3 = sansserif */
}


/* PAUSE: Pause until the user enters a keystroke. If the        */
/* key is an ESC, then exit program, else simply return.         */

void
Pause(void)
{
	int c;
	char buf[ 80 ];

	c = getch();		/* Read a character from kbd     */

    if (ESC == c)
    {				/* Does user wish to leave?  */
    closegraph();       /* Change to text mode       */
	exit(1);		/* Return to OS          */
    }
	if (0 == c)
	{				/* Did user hit a non-ASCII key? */
	c = getch();		/* Read scan code for keyboard   */
    }
    sprintf(buf, "NSEA Cycler: iteration %ld", iter);
    MainWindow(buf);
}

/* Display the info line for the main window */

void MainWindow( char *message )
	{
	BYTE far *scrnPtr = MK_FP( 0xA000, 0x0000 );
	int i;

	i = ( ( textheight( "A" ) * 2 ) + 6 ) * 80;
	while( i-- )
		*scrnPtr++ = 0;
	outtextxy( MaxX / 2, 2, message );
	}

/* STATUSLINE: Display a status line at the bottom of the screen.    */

void
StatusLine(char *msg)
{
	int height, colour;

	colour = getcolor();
	setcolor( LIGHTGRAY );
    changetextstyle(DEFAULT_FONT, HORIZ_DIR, 1);

    height = textheight("H");	/* Detemine current height      */
    rectangle(0, MaxY - (height + 4), MaxX, MaxY);
	outtextxy(MaxX / 2, MaxY - (height + 1), msg);
	changetextstyle( 1, HORIZ_DIR, 1 );	/* Restore previous text style */
	setcolor( colour );
}

/* */
/* CHANGETEXTSTYLE: similar to settextstyle, but checks for  */
/* errors that might occur while loading the font file.      */
/* */

void
changetextstyle(int font, int direction, int charsize)
{
    int ErrorCode;

    graphresult();		/* clear error code      */
    settextstyle(font, direction, charsize);
    ErrorCode = graphresult();	/* check result          */
    if (ErrorCode != grOk)
    {				/* if error occured      */
	closegraph();
	printf(" Graphics System Error: %s\n", grapherrormsg(ErrorCode));
	exit(1);
    }
}

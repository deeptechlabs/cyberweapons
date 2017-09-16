/*
 * Test driver for scoring stuff
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"


extern	str2gsi();

gsinfo	mygsi;
int		kwnbuf[100], gssbuf[100];

/* Test routine for statistics. */
main(argc, argv)
int		argc;
char	*argv[];
{
	char	*p;
	int		c, i;
	float	h;
	char	plainbuf[BLOCKSIZE+1];
	int		pvec[BLOCKSIZE+1];
	float	pscore, fscore;
	int		length;
	gsinfo	*gsi;
	char	str[100];

	printf("\nStatistics Test driver.  Type a line to see its score.\n\n");

	load_1stats_from("mss.stats");
	load_2stats_from("mss-bigram.stats");

	gsi = &mygsi;
	gsi->cknown = kwnbuf;
	gsi->cguessed = gssbuf;

	while (TRUE) {
		length = 0;
		for (p = plainbuf ; (c=read_char(stdin)) != EOL ; *p++ = c )  {
			length++;
			}
		*p = NULL;

		stripdots(plainbuf, str);
		str2pvec(str, pvec);
		pscore = pvec_1score(pvec);
		printf("pvec_1score is %5.3f", pscore);
/*
		pscore = var_1score(pvec);
		printf("var_1score is %5.3f", pscore);

		pscore = prob_1score(pvec);
		printf(", and prob_1score is %.3e", pscore);
*/

		str2gsi(plainbuf, gsi);
		pscore = gsi_score(gsi);
		printf(", and gsi_score is %5.3f", pscore);

		printf("\n");
		}
}


/* Fill in guess info block from string.  Treat all chars as
 * consecutive, except "." means unknown.
 */
str2gsi(str, gsi)
char	*str;
gsinfo	*gsi;
{
	int		cpos_index, guessed_index;

	cpos_index = 0;
	guessed_index = 0;
	while (*str != NULL)  {
		if (*str == '.')  {
			(gsi->cguessed)[guessed_index] = NONE;
			}
		else {
			gsi->cpos[cpos_index] = guessed_index;
			cpos_index++;
			(gsi->cguessed)[guessed_index] = 0377 & (*str);
			}
		(gsi->cknown)[guessed_index] = NONE;
		guessed_index++;
		str++;
		}
	gsi->cpos[cpos_index] = NONE;
	(gsi->cknown)[guessed_index] = NONE;
	(gsi->cguessed)[guessed_index] = NONE;
}

/* Copy in to out deleting the character "."
 */
stripdots(in, out)
char	*in, *out;		/* Null terminated strings. */
{
	while (*in != NULL)  {
		if (*in != '.')
			*out++ = *in++;
		else
			in++;
		}
	*out = NULL;
}


key	u_getkey()
{
}

keyer	topktab[] ={{0, NULL}};


char	*quitcmd()
{
	exit(0);
}

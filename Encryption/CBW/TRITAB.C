/*
 * Operations to load and print the table of trigrams.
 */

#include	<math.h>
#include	<stdio.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"
#include	"autotri.h"



#define	DEFAULTTRIGLIST	"trigrams.txt"
int		trig_loaded = FALSE;

/* This number is the probability that a randomly selected trigram
 * is not in the table of trigrams.
 */
float	trig_other_prob;


/* Table of trigrams with their probabilities.
 * The last entry has trig_ent.trigram == NULL.
 * This table is also be used as a priority queue.
 */
int			trig_tab_next;			/* For priority queue. */
trig_ent	trig_tab[TRIGTABSZ];



/* The following buffer is used to store all the trigram
 * strings read from the file.
 * trig_buf_next points to the net free character.
 */
char	*trig_buf_next;
char	trig_buf[TRIGBUFSZ];



/* Load the trigram table from the named file.
 */
load_tri_from(filename)
char	*filename;
{
	FILE	*inp;

	if ((inp = fopen(filename, "r")) == NULL)  {
		printf("\nCannot open %s to read trigram stats.\n", filename);
		exit(0);
		}
	load_tri(inp);
	fclose(inp);
}


/* Load trigram table from the given stream.
 * Input format:
 * <Total number of trigrams>
 * <blank line>
 * <Count for a particular trigram><space><Chars in the particular trigram>
 * ...
 * <Count for a particular trigram><space><Chars in the particular trigram>
 * <blank line>
 * <End of file>
 */
load_tri(inp)
FILE	*inp;
{
	int		i,n;
	int		tmp;
	int		c;
	float	v, trigram_prob;
	float	etotal, ctotal;
	char	*trigram_start;

	trig_loaded = TRUE;
	trig_tab_next = 0;
	trig_buf_next = trig_buf;
	trig_other_prob = 1.0;
	trig_tab[0].trigram = NULL;

	if (fscanf(inp, "%d", &tmp) != 1)  {
		printf("\nError while getting total trigram count.\n");
		exit(0);
		}
	etotal = tmp;
	ctotal = 0.0;

	if (fscanf(inp, "\n") != 0)  {
		printf("\nError while skipping blank line in trigram file.\n");
		return;
		}

	while (TRUE) {
		if ((n = fscanf(inp, "%d", &tmp)) != 1)  {
			if (n == 0) break;
			if (n == EOF) break;
			printf("\nError getting character count from trigram file.\n ");
			return;
			}
		v = tmp;
		ctotal += v;
		trigram_prob = v/etotal;
		trig_other_prob -= trigram_prob;

		c = read_char(inp);		/* Skip the space. */
		trigram_start = trig_buf_next;
		while (TRUE) {
			c = read_char(inp);
			if (c == EOL)  break;
			if (trig_buf_next >= &trig_buf[TRIGBUFSZ-1]) {
				printf("\nOverflowed Trigram buffer.\n");
				exit(0);
				}
			*trig_buf_next++ = c & CHARMASK;
			}
		if (trig_buf_next >= &trig_buf[TRIGBUFSZ-1]) {
			printf("\nOverflowed Trigram buffer.\n");
			exit(0);
			}
		*trig_buf_next++ = NULL;

		trig_tab[trig_tab_next].prob = trigram_prob;
		trig_tab[trig_tab_next].trigram = trigram_start;
		trig_tab[trig_tab_next].notused = 0;
		trig_tab_next++;
		}

}


/* Print the trigram table onto a stream.
 */
print_tri(out)
FILE	*out;
{
	int		i;

	fprintf(out, "\n");
	for (i = 0 ; trig_tab[i].trigram != NULL ; i++)  {
		fprintf(out, "'%s'\t%7.4f\n", trig_tab[i].trigram, trig_tab[i].prob);
		}
	fprintf(out, "\n");
}

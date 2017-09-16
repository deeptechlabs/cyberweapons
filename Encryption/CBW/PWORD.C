/*
 * Automatic guessing based on probable words.
 *
 * Bob Baldwin, February 1985.
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"
#include	"cipher.h"
#include	"autotri.h"


#define	DEBUG	FALSE

#define	NWORDS		100
#define WDBUFSZ		(8*NWORDS)
#define	WDPERMSZ	40
#define	PWDLABEL1	"Probable word search -- Please Wait"
#define	PWDLABEL2	"Probable word search -- Done"
#define	PWDHELP		"F3 enters guess, ^G undoes it."


extern	char	mcbuf[];
extern	ecinfo	gecinfo;
extern	atrinfo gatrinfo;
extern	atrdraw(), atrfirst(), atrenter(), atrundo();
extern	char	*pwd_init();

/* Gloabal State. */
char	*word_tab[NWORDS];
char	word_buf[WDBUFSZ];

keyer	pwdktab[] = {
		{CACCEPT, atrenter},
		{CUNDO, atrundo},
		{CGO_UP, jogup},
		{CGO_DOWN, jogdown},
		{CGO_LEFT, jogleft},
		{CGO_RIGHT, jogright},
		{0, NULL},
};

/* Routine invoked by user to search of a list of probable words.
 * The window is drawn empty, and then filled in with the guess.
 * Return NULL if command completes ok.
 */
char	*pwdguess(str)
char	*str;			/* Command line */
{
	gwindow	*pwd;
	atrinfo	*pwdi;
	ecinfo	*ecbi;
	int		*dbsperm;
	float	max_score;
	char	*errmsg;
	int		i;
	char	filename[MAXWIDTH+1];

	if ((i = sscanf(str, "%*[^:]: %s %*[^:]: %f",
		filename, &max_score)) != 2)  {
			return("Could not parse both arguments.");
		}

	pwd = &gbstore;
	pwdi = &gatrinfo;
	dbsperm = refperm(dbsgetblk(&dbstore));
	errmsg = pwd_init(filename, mcbuf, dbsperm, pwdi);
	if (errmsg != NULL)  return(errmsg);

	ecbi = pwdi->eci;
	pwdi->min_total_chars = 1;
	pwdi->max_score = max_score;
	pwdi->min_wire_chars = 0;

	gbsswitch(pwd, ((char *) pwdi), pwdktab, atrfirst, wl_noop, atrdraw);

	gblset(&gblabel, PWDLABEL1);
	atrdraw(pwd);
	fflush(stdout);

	pwd_autoguess(pwdi);
	decode(ecbi->ciphertext, ecbi->plaintext, ecbi->perm);

	gblset(&gblabel, PWDLABEL2);
	atrdraw(pwd);

	return(NULL);
}


/* Load a word table from the given file.
 * Format is a word on each line terminated by a blank line
 * Returns error message or NULL.
 */
char *wtab_load_from(filename, charbuf, buffree, wtab, tabsize)
int		buffree, tabsize;
char	*filename, *charbuf;
char	*wtab[];
{
	FILE	*inp;
	char	*wordstart;
	int		wordindex, wordlength;
	int		c;

	if ((inp = fopen(filename, "r"))== NULL)  {
		return("Cannot open file to read probable words.");
		}

	wordindex = 0;
	while(wordindex < tabsize-1)  {
		wordstart = charbuf;
		wordlength = 0;
		while ((c = read_char(inp)) != EOL) {
			*charbuf++ = c;
			wordlength++;
			buffree--;
			if (buffree <= 1)  break;
			}
		*charbuf++ = NULL;
		buffree--;
		if (wordlength == 0  ||  buffree <= 0)  break;
		wtab[wordindex++] = wordstart;
		}

	wtab[wordindex] = NULL;

	fclose(inp);
	return(NULL);
}



/* Fill in probable word info from given ciphertext block.
 * The filter parameters are not set by this routine.
 */
char *pwd_init(filename, cipher, perm, pwdi)
char	*filename;
char	cipher[];
int		perm[];
atrinfo	*pwdi;
{
	int		i;
	char	*errmsg;

	pwdi->eci = &gecinfo;
	errmsg = wtab_load_from(filename, word_buf, WDBUFSZ, word_tab, NWORDS);
	if (errmsg != NULL)  return(errmsg);
	ec_init(cipher, perm, pwdi->eci);
	pwd_guess_init(pwdi);
	return(NULL);
}


/* Per guess initialization.
 */
pwd_guess_init(pwdi)
atrinfo	*pwdi;
{
	pwdi->best_trigram = NULL;
	pwdi->best_score = 10.0;
	pwdi->gcount = 0;
	pwdi->total_score = 0;
	pwdi->best_pvec[0] = NONE;
	pwdi->best_permvec[0].x = NONE;
}



/* Score a word at a given position.
 * Fills in permvec and pvec.
 */
float	pwd_score(pwdi, word, pos, permvec, pvec)
atrinfo		*pwdi;
char		*word;
int			pos;
perment		permvec[];
int			pvec[];
{
	int		added, wordlen;
	char	*p;
	float	score;
	ecinfo	*eci;

	p = word;
	wordlen = 0;
	while (*p++ != NULL)  wordlen++;
	eci = pwdi->eci;
	added = permvec_from_string(pwdi->eci, word, pos, permvec);
	if (added == ERROR)  return(-1.0);
	added = permvec2pvec(pwdi->eci, permvec, pvec, -1, -1);
	if (added == ERROR)  return(-1.0);
	if (added < pwdi->min_total_chars) {
		return(-1.0);
		}

	score = pvec_1score(pvec);
#if DEBUG
	print_pvec(stdout, pvec);
	printf("Putting %s at %d, gets a score of %f\n",
	        word, pos, score);
#endif
	return(score);
}


/* Select the best probable word for a given position.
 * Returns pointer to the word, or NULL.
 * Fills in pwdi with additional information.
 * Filtering parameters are passed in pwdi.
 */
char	*pwd_best(pwdi, pos)
atrinfo	*pwdi;
int		pos;
{
	int		windex;
	float	score;
	perment	permvec[WDPERMSZ];
	int		pvec[BLOCKSIZE+1];

	pwd_guess_init(pwdi);

	for (windex = 0 ; word_tab[windex] != NULL ; windex++)  {
		score = pwd_score(pwdi, word_tab[windex], pos, permvec, pvec);
		if (score < 0.0)  continue;
		pwdi->gcount++;
		pwdi->total_score += score;
		if (score < pwdi->best_score) {
			pwdi->best_score = score;
			pwdi->best_trigram = word_tab[windex];
			pvec_copy(pvec, pwdi->best_pvec);
			permvec_copy(permvec, pwdi->best_permvec, WDPERMSZ);
			}
		}
	if (pwdi->best_score < pwdi->max_score)
		{return(pwdi->best_trigram);}
	else
		{return(NULL);}
}



/* Perform automatic guessing given a set of
 * filter parameters in an atrinfo structure.
 */
pwd_autoguess(pwdi)
atrinfo	*pwdi;
{
	int		pos;
	char	*word;

	for (pos = 0 ; pos < BLOCKSIZE ; pos++) {
		word = pwd_best(pwdi, pos);
		if (word != NULL) {
			accept_permvec(pwdi, pwdi->best_permvec);
			}
		}
}

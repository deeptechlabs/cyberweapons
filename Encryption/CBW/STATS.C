/*
 * Statistics routines.
 *
 * Robert W. Baldwin, January 1985.
 * Scoring based on letter pairs added by Bob Baldwin May 1985.
 */


#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"


#define STANDALONE	FALSE



/* Globals */
int		stats1loaded = FALSE;	/* True if letter stats loaded. */
char	*letterstats;			/* Filename to find single letter counts. */
int		stats2loaded = FALSE;	/* True if letter pair stats loaded. */
char	*bigramstats;			/* Filename to find letter pair counts. */


/* This array contains the single letter frequencies.
 * That is, prob[i] is the probability that a randomly selected
 * plaintext character has ascii value i.
 */
float	prob[MAXCHAR+1];
float	pmean, pvar;			/* Mean and variance of above. */


/* This array contains the base ten logarithms of the single
 * letter frequencies (probabilities) of ASCII characters.
 * The frequencies are between 0 and 1, so the enteries in the
 * table are between minus infinity and 0.
 * The log of a vanishingly small frequency is represented as
 * zero rather than some large negative number.
 * The expected value of logprob[c] for a randomly selected
 * character, c, is given by logmean.  The variance of logprob[c]
 * is given by logvar.  The standard deviation is in logsd.
 */
float	logprob[MAXCHAR+1];
float	logmean, logvar, logsd;


/* This array contains the bigram (letter pair) frequencies.
 * That is, biprob[i][j] is the probability that a randomly selected
 * pair of adjacent plaintext characters is Ai, Aj.  Where Ai
 * is the ith letter of the alphabet (0 = 'A' or 'a', and
 * 26 = space or other non-alphabetic).
 * Eventually this will be generalized to include an arbitrary
 * character translation table to handle punctuation and to allow
 * groups of characters such as (, <, {, and [ to be treated the same.
 * 
 * The array slbiprob is the single letter frequencies taken from the
 * same sources as biprob[][].
 */
float	biprob[MXBIINDEX][MXBIINDEX];
float	slbiprob[MXBIINDEX];


/* The array is used to map from 7-bit ascii to indices in the biprob
 * and related arrays.  The variable nbichars is set to the next index
 * to use in the biprob array.
 */
int		char_bimap[MAXCHAR+1];
int		nbichars;


/* This array contains the base ten logarithms of the letter pair
 * frequencies (biprob[][]).
 * The frequencies are between 0 and 1, so the enteries in the
 * table are between minus infinity and 0.
 * The log of a vanishingly small frequency is represented as
 * zero rather than some large negative number.
 * The expected value of bilogprob[c] for a randomly selected
 * character, c, is given by bilogmean.  The variance of bilogprob[c]
 * is given by bilogvar.  The standard deviation is in bilogsd.
 */
float	bilogprob[MXBIINDEX][MXBIINDEX];


/* This vector contains the base ten logarithms of the single letter
 * frequencies which are derived from biprob[][].
 * They are used to compute the log of the conditional probabilities
 * of letter pairs, given a known value for either the first or
 * second character.
 * Specifically: log( prob(XY given X=Ai) ) equals
 *    log( prob(XY) / prob(Ai) ) which equals 
 *    bilogprob[X][Y] - sllogprob[Ai].
 */
float	sllogprob[MXBIINDEX];


/* The scoring function that uses letter pair frequencies is based
 * on a statistic that has a computable mean and variance (and
 * standard deviation).  The are stored in the following variables.
 */
float	score2_mean, score2_var, score2_sd, score2_scale;
float	score1_mean, score1_var, score1_sd, score1_scale;


#if STANDALONE
#define	filename		"/usr/baldwin/Ecrypt/mss-bigram.stats"
main()
{
	FILE	*inp;

	load_2stats_from(filename);
	print_2stats(stdout);
}
#endif



/* Score the given plaintext block.  Returns a floating point number.
 * For now a stud.
 */
float	score(pblock)
int		pblock[];
{
	int		pchar;
	int		i;
	float	score;

	score = 0.0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		pchar = pblock[i];
		if (pchar == -1)  continue;
		if (pchar == ' ')			{score += 0.1;}
		else if (lletter(pchar))	{score += 0.1;}
		else if (uletter(pchar))	{score += 0.05;}
		else if (printable(pchar))	{score += 0.02;}
		else if (pchar == '\t' || pchar == '\n' || pchar == '\f')
									{score += 0.05;}
		else if ('0' <= pchar && pchar <= '9')
									{score += 0.05;}
		else 						{score -= 0.4;}
		}
	return(score);
}


/* Score a vector of integers that represent characters.
 * The vector is terminated by a value of NONE.
 * The returned score is the number of standard deviations
 * that the observed statistics differs from its expected value.
 * Scores are positive with low scores being better.
 * A negative score indicates an impossible plaintext value.
 */
float	pvec_1score(pvec)
int	*pvec;
{
	int		i;
	int		c;
	float	tmp, sum, count, score;

	if (!stats1loaded)  {
		load_1stats_from(letterstats);
		}

	count = 0.0;
	sum = 0.0;
	while (*pvec != NONE)  {
		count += 1.0;
		c = *pvec++;
		if (c != c & CHARMASK)  return(-1.0);
		tmp = logprob[c & CHARMASK];
		if (tmp == 0.0)  return(-1.0);
		sum += tmp;
		}

	if (count == 0.0)  return(-1.0);
	tmp = (sum / count) - logmean;
	tmp = tmp > 0 ? tmp : 0.0 - tmp;
	score = tmp / (logsd / sqrt(count));
/*	printf("  dividing by logsd yields %g", score);
	tmp = tmp * tmp;
	tmp = (tmp * count) / logvar;
	tmp = exp(-0.5 * tmp);
	printf("\nThe exponential yields %g", tmp);
	printf("\n");
	score = sqrt(count) * exp((0 - tmp)/2.0);
*/
	return(score);
}


/* Score a vector of integers that represent characters.
 * The vector is terminated by a value of NONE.
 * Scoring is based on ratio of observed and expected variance.
 */
float	var_1score(pvec)
int	*pvec;
{
	int		i;
	int		c;
	float	tmp, sum, count, score;

	if (!stats1loaded)  {
		load_1stats_from(letterstats);
		}

	count = 0.0;
	sum = 0.0;
	while (*pvec != NONE)  {
		count += 1.0;
		c = *pvec++;
		if (c != c & CHARMASK)  return(0.0);
		tmp = logprob[c & CHARMASK];
		if (tmp == 0.0)  return(0.0);
		tmp = tmp - logmean;
		tmp = tmp * tmp;
		sum += tmp;
		}

	if (count == 0.0)  return(0.0);
	score = sum / (count * logvar);
	return(score);
}


/* Score a vector of integers that represent characters.
 * The vector is terminated by a value of NONE.
 * Score is the probability that the given characters
 * were drawn from english.
 * NOTE: doesn't correctly handle repeated letters.
 */
float	prob_1score(pvec)
int	*pvec;
{
	int		i;
	int		c;
	float	tmp, product, count, score;

	if (!stats1loaded)  {
		load_1stats_from(letterstats);
		}

	count = 0.0;
	product = 1.0;
	while (*pvec != NONE)  {
		count += 1.0;
		c = *pvec++;
		if (c != c & CHARMASK)  return(0.0);
		product *= prob[c] * count;
		}

	if (count == 0.0)  return(0.0);
	score = product;
	return(score);
}


/* Score a guess based on letter pair frequencies.
 * The returned score is the number of standard deviations
 * that the observed statistics differs from its expected value.
 * Scores are positive with low scores being better.
 * A negative score indicates an impossible plaintext value.
 */
float	gsi_2score(gsi)
reg		gsinfo	*gsi;
{
	float	score;
	float	total;
	float	tmp;
	int		nchars;
	int		i;
reg	int		pos;	
reg	int		c;
reg	int		center_letter;
	int		left_letter, right_letter;
	float	pair_score;

	if (!stats2loaded)  {
		load_2stats_from(bigramstats);
		}

	nchars = 0;
	total = 0.0;
	for (i = 0 ; (pos = gsi->cpos[i]) != NONE ; i++)  {
		nchars++;
		c = (gsi->cguessed)[pos];
		center_letter = char_bimap[c & CHARMASK];
		if (sllogprob[center_letter] == 0.0)
			return(-1.0);

		if (pos == 0) {
			total += sllogprob[center_letter];
			}
		else {
			c = (gsi->cknown)[pos - 1];
			if (c == NONE)  {
				c = (gsi->cguessed)[pos - 1];
				}
			if (c == NONE)  {
				total += sllogprob[center_letter];
				}
			else {
				left_letter = char_bimap[c & CHARMASK];
				pair_score = bilogprob[left_letter][center_letter];
				if (pair_score == 0.0)
					return(-1.0);
				total += pair_score - sllogprob[center_letter];
				}
			}

		if (pos == (BLOCKSIZE - 1)) {
			total += sllogprob[center_letter];
			}
		else {
			c = (gsi->cknown)[pos + 1];
			if (c == NONE)  {
				c = (gsi->cguessed)[pos + 1];
				}
			if (c == NONE)  {
				total += sllogprob[center_letter];
				}
			else {
				right_letter = char_bimap[c & CHARMASK];
				pair_score = bilogprob[center_letter][right_letter];
				if (pair_score == 0.0)
					return(-1.0);
				total += pair_score - sllogprob[center_letter];
				}
			}
		}

	if (nchars == 0)
		return(-1.0);
	tmp = (total / nchars) - score2_mean;
	tmp = tmp > 0.0 ? tmp : 0.0 - tmp;
	score = tmp / (score2_sd / isqrt[nchars]);
	return(score);
}


/* Score a guess based on single letter frequencies.
 * The returned score is the number of standard deviations
 * that the observed statistics differs from its expected value.
 * Scores are positive with low scores being better.
 * A negative score indicates an impossible plaintext value.
 */
float	gsi_1score(gsi)
reg		gsinfo	*gsi;
{
reg	int		pos;
	int		i;
	int		c;
	int		nchars;
	float	sum, score;
reg	float	tmp;

	if (!stats1loaded)  {
		load_1stats_from(letterstats);
		}

	nchars = 0;
	sum = 0.0;
	for (i = 0 ; (pos = gsi->cpos[i]) != NONE ; i++)  {
		nchars++;
		c = (gsi->cguessed)[pos];
		tmp = logprob[c & CHARMASK];
		if (tmp == 0.0)
			return(-1.0);
		sum += tmp;
		}

	if (nchars == 0)
		return(-1.0);
	tmp = (sum / nchars) - logmean;
	tmp = tmp > 0 ? tmp : 0.0 - tmp;
	score = tmp / (logsd / isqrt[nchars]);

	return(score);
}


/* Compute expected value of a scoring function given
 * a vector of probabilities for values and a vector of
 * scores for each value.
 */
float	vec_mean(probvec, scorevec, maxindex)
float	*probvec;
float	*scorevec;
int		maxindex;
{
	int		i;
	float	mean;

	mean = 0.0;
	for (i = 0 ; i <= maxindex ; i++) {
		mean += (*probvec++) * (*scorevec++);
		}
	return(mean);
}


/* Compute variance of a scoring function given
 * a vector of probabilities for values and a vector of
 * scores for each value.
 */
float	vec_variance(probvec, scorevec, maxindex)
float	*probvec;
float	*scorevec;
int		maxindex;
{
	int		i;
	float	var, mean;
	float	delta;

	mean = vec_mean(probvec, scorevec, maxindex);
	var = 0.0;
	for (i = 0 ; i <= maxindex ; i++) {
		delta = (*scorevec++) - mean;
		var += (*probvec++) * (delta * delta);
		}
	return(var);
}


/* Read from given stream to set up logprob table and constants
 * logmean and logvar.
 *
 * The table format is:
 * <Total count>
 * <Blankline>
 * <Count><space><One or more slashified characters to share that count>
 *  ...
 * <Count><space><One or more slashified characters to share that count>
 * <Blankline>
 * <EOF>
 */
load_1stats(inp)
FILE	*inp;
{
	int		i,n;
	int		tmp;
	int		c;
	float	v, lv, fv;
	float	etotal, ctotal;

	stats1loaded = TRUE;

	for (i = 0 ; i <= MAXCHAR ; i++)  logprob[i] = 0.0;

	if (fscanf(inp, "%d", &tmp) != 1)  {
		printf("Error while getting total");
		return;
		}
	etotal = tmp;
	ctotal = 0.0;

	if (fscanf(inp, "\n") != 0)  {
		printf("Error while skipping blank line");
		return;
		}

	while (TRUE) {
		if ((n = fscanf(inp, "%d", &tmp)) != 1)  {
			if (n == 0) break;
			if (n == EOF) break;
			printf("Error while getting character count");
			return;
			}
		v = tmp;
		ctotal += v;
		fv = v/etotal;
		if (fv != 0.0)  {lv = log10(fv);}
		else {lv = 0.0;}

		c = read_char(inp);		/* Skip the space. */
		while (TRUE) {
			c = read_char(inp);
			if (c == EOL)  break;
			prob[c&CHARMASK] = fv;
			logprob[c&CHARMASK] = lv;
			}
		}

	if (etotal != ctotal) {
		printf("Expected total is %f.  Actual total is %f.\n",etotal,ctotal);
		}

	logmean = vec_mean(prob, logprob, MAXCHAR);
	logvar  = vec_variance(prob, logprob, MAXCHAR);
	logsd = sqrt(logvar);
	score1_mean = logmean;
	score1_var = logvar;
	score1_sd = logsd;
	score1_scale = sqrt(2 * PI * score1_var);
	pmean = vec_mean(prob, prob, MAXCHAR);
	pvar = vec_variance(prob, prob, MAXCHAR);
}


/* Load the letter pair statistics from the given file name.
 */
load_2stats_from(statfname)
char	*statfname;		/* Full path name of file with statistics. */
{
	FILE	*inp;

	if ((inp = fopen(statfname, "r")) == NULL) {
		printf("\nCan't open %s to read letter statistics\n", statfname);
		exit(0);
		}
	load_2stats(inp);
	fclose(inp);
}


/* Read from given stream to set up bilogprob table and constants
 * bilogmean, bilogsd, and bilogvar.
 *
 * The format of the statistics file is: [This should be more general.]
 * <Total count>
 * <Blankline>
 * <single letter counts>
 * <line with the chars '***'>
 * <double letter counts>
 * <line with the chars '***'>
 * <mean of matrix>
 * <variance of matrix>
 * <standard deviation of matrix>
 * <Blankline>
 * <EOF>
 *
 * Where single letter counts also define the mapping from ascii chars to
 * distinguished letters (i.e., all open brackets are treated the same).
 * The single letter format is:
 * <Count><space><One or more slashified characters to share that count>
 *  ...
 * <Count><space><One or more slashified characters to share that count>
 * NOTE: the first entry should be for a low probability letter because the
 * default mapping for unknown chars is zero.  See code for details.
 *
 * The double letter format is:
 * <Count><space><Representative of first letter group><Rep of second letter>
 *  ...
 * <Count><space><Representative of first letter group><Rep of second letter>
 *
 * For example if 'T' and 't' are treated the same, a double letter entry
 * might look like: "1247 TT" and count for Tt, tT, tt, and TT.
 */
load_2stats(inp)
FILE	*inp;
{
register	int		i,j;
    int		n;
	int		tmp;
	int		c;
	int		left_index, right_index;
	float	v, lv, fv;
	float	etotal, ctotal;
	char	linebuf[300];

	stats2loaded = TRUE;
	nbichars = 0;

	for (i = 0 ; i < MXBIINDEX ; i++)  {
		sllogprob[i] = 0.0;
		slbiprob[i] = 0.0;
		for (j = 0 ; j < MXBIINDEX ; j++)  {
	 		bilogprob[i][j] = 0.0;
			biprob[i][j] = 0.0;
			}
		}

	for (i = 0 ; i < MAXCHAR+1 ; i++)
		char_bimap[i] = 0;		/* Default index if char unknown. */

	if (fscanf(inp, "%d", &tmp) != 1)  {
		printf("Error while getting total");
		exit(0);
		}
	etotal = tmp;

	if (fscanf(inp, "\n") != 0)  {
		printf("Error while skipping blank line before single letters");
		exit(0);
		}

	ctotal = 0.0;
	while (TRUE) {
		if ((n = fscanf(inp, "%d", &tmp)) != 1)  {
			if (n == 0) break;
			if (n == EOF) break;
			printf("Error while getting character count (singles)");
			exit(0);
			}
		v = tmp;
		ctotal += v;
		fv = v/etotal;
		if (fv == 0.0)
			lv = 0.0;
		else
			lv = log10(fv);

		c = read_char(inp);		/* Skip the space. */
		while (TRUE) {
			c = read_char(inp);
			if (c == EOL)  break;
			char_bimap[c & CHARMASK] = nbichars;
			slbiprob[nbichars] = fv;
			sllogprob[nbichars] = lv;
			}
		nbichars++;
		}

	if (etotal != ctotal) {
		printf("Expected total is %f.  Actual total is %f for singles.\n",
				etotal, ctotal);
		exit(0);
		}


	if (fscanf(inp, "***\n") != 0)  {
		printf("Error on delimiter before letter pairs");
		exit(0);
		}

	ctotal = 0.0;
	while (TRUE) {
		if ((n = fscanf(inp, "%d", &tmp)) != 1)  {
			if (n == 0) break;
			if (n == EOF) break;
			printf("Error while getting character count (pairs)");
			exit(0);
			}
		v = tmp;
		ctotal += v;
		fv = v/etotal;
		if (fv == 0.0)
			lv = 0.0;
		else
			lv = log10(fv);

		c = read_char(inp);		/* Skip the space. */
		c = read_char(inp);		/* First letter. */
		if (c == EOL)  {
			printf("Line ends before letter pair");
			exit(0);
			}
		left_index = char_bimap[c & CHARMASK];
		c = read_char(inp);		/* Second letter. */
		if (c == EOL)  {
			printf("Line ends in middle of letter pair");
			exit(0);
			}
		right_index = char_bimap[c & CHARMASK];

		biprob[left_index][right_index] = fv;
		bilogprob[left_index][right_index] = lv;
		}

	if (etotal != ctotal) {
		printf("Expected total is %f.  Actual total is %f for pairs.\n",
				etotal, ctotal);
		exit(0);
		}

	if (fscanf(inp, "***\n") == 0)  {
		if (fscanf(inp, "%f", &score2_mean) != 1)  {
			printf("Error reading mean.");
			exit(0);
			}
		if (fscanf(inp, "%f", &score2_var) != 1)  {
			printf("Error reading variance.");
			exit(0);
			}
		if (fscanf(inp, "%f", &score2_sd) != 1)  {
			printf("Error reading standard deviations.");
			exit(0);
			}
		score2_scale = sqrt(2 * PI * score2_var);
		approx_init();
		return;
		}

	stats2();
	printf("Mean: %f, Var: %f, SD: %f\n", score2_mean, score2_var, score2_sd);
}


/* Compute scoring statistics for the letter pair frequencies.
 * Uses the globals: biprob[][], sllogbiprob[], and bilogprob[][].
 * Sets gobals: score2_mean, score2_var, score2_sd.
 */
stats2()
{
register	int	i,j,k;
	float	mean, var;
	float	weight, score;

	mean = 0.0;
	var = 0.0;
	for (i = 0 ; i < nbichars ; i++)
		for (j = 0 ; j < nbichars ; j++)  {
			if (slbiprob[j] == 0.0)
				continue;
			for (k = 0 ; k < nbichars ; k++) {
				weight = biprob[i][j] * biprob[j][k] / slbiprob[j];
				score = bilogprob[i][j] + bilogprob[j][k] - 2 * sllogprob[j];
				mean += weight * score;
				var += weight * score * score;
				}
			}
	var -= mean * mean;

	score2_mean = mean;
	score2_var = var;
	score2_sd = sqrt(score2_var);
	score2_scale = sqrt(2 * PI * score2_var);

	approx_init();
}


/* Print the bigram statistics.
 */
print_2stats(out)
FILE	*out;
{
	float	sllog_mean;
	float	sllog_var;
	float	lev_mean, lev_var;
	float	rev_mean, rev_var;

	fprintf(out, "\t\tBigram Statistics\n");
	fprintf(out, "Score2_mean is %f", score2_mean);
	fprintf(out, ", score2_var is %f", score2_var);
	fprintf(out, ", score2_sd is %f", score2_sd);
	fprintf(out, "\nnbichars is %d", nbichars);
	fprintf(out, "\n");

	sllog_mean = vec_mean(slbiprob, sllogprob, nbichars);
	sllog_var = vec_variance(slbiprob, sllogprob, nbichars);
	fprintf(out, "sllog_mean is %f", sllog_mean);
	fprintf(out, ", sllog_var is %f", sllog_var);
	fprintf(out, "\n");
}



/* Print the first order log statistics on a stream.
 */
print_1stats(out)
FILE	*out;
{

	fprintf(out, "Single letter frequencies\n");
	fprintf(out, "\nExpected value of prob is %f.  Variance is %f.\n",
	       pmean, pvar);
	print_stat_tab(out, prob, MAXCHAR);

	fprintf(out, "\nExpected value of logprob is %f.  Variance is %f.\n",
	       logmean, logvar);
	fprintf(out, "Log of single letter frequencies\n");
	print_stat_tab(out, logprob, MAXCHAR);
}


/* Dumpa statistics table on to a stream.
 */
print_stat_tab(out, table, maxindex)
FILE	*out;
float	table[];
int		maxindex;
{
	int		i;

	for (i = 0 ; i <= maxindex ; i++) {
		if (i % 8 == 0)  fprintf(out, "\n");
		fprintf(out, "%7.4f ", table[i]);
		}
	fprintf(out, "\n");
}


/* Load the first order statistics from the given file name.
 */
load_1stats_from(statfname)
char	*statfname;
{
	FILE	*inp;

	if ((inp = fopen(statfname, "r")) == NULL) {
		printf("\nCan't open %s to read letter statistics\n", statfname);
		exit(0);
		}
	load_1stats(inp);
	fclose(inp);
}


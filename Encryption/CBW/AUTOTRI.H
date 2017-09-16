/*
 * Definitions for automatically guessing with trigrams. 
 */


#define	PERMSZ		20
#define	TRIGTABSZ	150
#define	TRIGBUFSZ	(4*(TRIGTABSZ+1))



#define	trig_ent	struct xtrigent
trig_ent	{
		float	prob;		/* A priori probability of this trigram. */
		char	*trigram;	/* Null for last entry in table. */
		int		notused;	/* For compatibility with pqueue. */
		};


#define	atrinfo	struct xatrinfo
atrinfo	{
		ecinfo		*eci;
		/* A guess must have a better score than this field. */
		float		max_score;
		/* A guess must deduce atleast this many chars. */
		int			min_total_chars;
		/* Each wire of the guess must deduce this many chars. */
		int			min_wire_chars;
		char		*best_trigram;
		float		best_score;
		int			gcount;			/* Total number of guesses. */
		float		total_score;	/* Their cummulative score. */
		/* NONE terminated string of the chars deduced by the best trigram. */
		/* Does not include the trigram itself. */
		int			best_pvec[BLOCKSIZE+1];
		/* Table of permutation wirings deduced by the best guess so far. */
		/* The table is terminated by a perment with x == NONE. */
		perment		best_permvec[PERMSZ];
		};


extern	trig_ent	trig_tab[];


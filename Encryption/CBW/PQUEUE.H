/*
 * Priority queue declarations.
 *
 * Bob Baldwin, February, 1985.
 */

extern	int		pque_full(/* pque_hdr */);
extern			pque_add(/* pque_hdr */);
extern			pque_init(/* pque_hdr, min_score, pque_tab, pque_size */);

#define	pqueue_ent	struct xpqueue_ent
pqueue_ent	{
		float	score;
		int		value1;
		int		value2;
		};

#define	pqueue_hdr	struct xpqueue_hdr
pqueue_hdr	{
		int			next_index;		/* Next free entry. */
		int			pque_size;		/* Number of entries. */
		float		max_score;		/* Score < max */
		pqueue_ent	*pque_tab;		/* Ptr to first entry. */
		};

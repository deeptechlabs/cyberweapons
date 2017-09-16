/*
 * Priority queue.
 *
 * Bob Baldwin, February, 1985.
 */

#include	<stdio.h>
#include	"pqueue.h"



/* Initialize a pqueue header with the given parameters.
 */
pque_init(pque_hdr, max_score, pque_tab, pque_size)
pqueue_hdr	*pque_hdr;
float		max_score;
pqueue_ent	*pque_tab;
int			pque_size;
{
	pque_hdr->next_index = 0;
	pque_hdr->pque_size = pque_size;
	pque_hdr->max_score = max_score;
	pque_hdr->pque_tab = pque_tab;
}


/* Return TRUE if the pqueue cannot hold another entry.
 */
int	pque_full(pque_hdr)
pqueue_hdr	*pque_hdr;
{
	return (pque_hdr->next_index >= pque_hdr->pque_size);
}


/* Add an entry to the priority queue.  Sorted lowest score first.
 * The queue header indicates the next free slot, the maximum
 * score (all scores in queue < max), and the size of the table.
 * If the pqueue is full the lowest scoring entry will be
 * thrown out.
 *
 * Implementation:  Find the first slot before sizelast+1 that
 * has a size less than the size arg.  Shuffle down the list
 * to create a hole and insert the new entry.
 */
pque_add(pque_hdr, score, value1, value2)
pqueue_hdr	*pque_hdr;
float		score;
int			value1;
int			value2;
{
	int			k;		/* Slot where new entry will go. */
	int			i;
	pqueue_ent	*pque;
	pqueue_ent	new_ent;

	if (score >= pque_hdr->max_score)  return;

	new_ent.score = score;
	new_ent.value1 = value1;
	new_ent.value2 = value2;
	pque = pque_hdr->pque_tab;

	for (k = 0 ; k < pque_hdr->next_index ; k++)  {
		if (pque[k].score > score)  break;
		}

	for (i = pque_hdr->next_index ; i > k ; i--)  {
		pque[i] = pque[i-1];
		}
	if (pque_hdr->next_index < pque_hdr->pque_size)
		pque_hdr->next_index++;

	pque[k] = new_ent;
}

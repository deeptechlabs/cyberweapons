/* 
 * Routines for operating on cipher blocks.
 *
 * Robert W. Baldwin, January 1985.
 */


#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"


#define	DEBUG	FALSE


/* Decode the cblock into pblock using perm.
 * Return FALSE if find a non-ascii character, else 1.
 */
decode(cblock, pblock, perm)
char	cblock[];
int		pblock[];
int		perm[];
{
int iplace;		/* Index into ciphertext block. */
int spchar;		/* Plaintext char not unshifted. */
int pchar;		/* Plaintext char. */
int	good;		/* Plaintext doesn't have any unacceptable chars in it. */

good = TRUE;
for (iplace = 0 ; iplace < BLOCKSIZE ; iplace++) {
	spchar = perm[(iplace+cblock[iplace])&MODMASK];
	if (spchar == -1) {
		pchar = -1;
		}
	else {
		pchar = (spchar-iplace) & MODMASK;
		if (notascii(pchar))  {
			good = FALSE;
			}
		}
	pblock[iplace] = pchar;
	}
return(good);
}


/* Searches for string in block.
 * Returns position it found that didn't have conflicts, or -1.
 * If found, it will add to perm all the deduced wirings.
 * If perm is not initially all -1, search will not accept any
 * position that conflicts with the initial wirings, nor will
 * it mutate any of those wirings.
 */
int	search(cipher, perm, initpos, thing)
char	*cipher;
int		*perm;
int		initpos;
char	*thing;		/* NULL terminated string. */
{
	int	iplace;		/* Current placement of trigram in plaintext block. */
	int i;			/* Index for initializing arrays. */
	int	pchar;		/* Plaintext character. */
	int	spchar;		/* Plaintext character cyclically shifted by its pos. */
	int	*spstkp;
	int	spstack[BLOCKSIZE];
	int	*scstkp;
	int	scstack[BLOCKSIZE];
	int	scchar;		/* Ciphertext character cyclically shifted by its pos. */
	int	offset;
	int	thinglen;
	char *p;

	p = thing;
	for (thinglen = 0 ; *p++ != 0 ; thinglen++) ;

  for (iplace = initpos ; iplace < BLOCKSIZE-thinglen ; iplace++) {
	spstkp = spstack;
	scstkp = scstack;
	for (offset = 0 ; offset < thinglen ; offset++) {
		pchar = ((int) thing[offset]);
		spchar = (pchar + iplace + offset) & MODMASK;
		scchar = (cipher[iplace + offset] + iplace + offset) & MODMASK;
		if ((perm[spchar] != -1  ||  perm[scchar] != -1)
		 && (perm[spchar] != scchar))  {
				while (spstkp > &spstack[0]) perm[*(--spstkp)] = -1;
				while (scstkp > &scstack[0]) perm[*(--scstkp)] = -1;
				goto nextplace;
				}
		perm[spchar] = scchar;
		*spstkp++ = spchar;
		perm[scchar] = spchar;
		*scstkp++ = scchar;
		}
	return(iplace);
	nextplace: ;
	}
  return(-1);
}


/* Fill in the pvec with the characters decoded from assuming
 * that the ciphertext character at position firstpos maps to
 * the plaintext character firstplain.
 * Return the number of characters added to pvec not counting
 * the termination character (NONE) that we always add.
 * If any of the characers decoded to non-ascii values, then
 * return ERROR (a negative number).
 * Also return ERROR if the guess would conflict with the ones already
 * in eci->perm.
 */
int	decode_class(eci, firstpos, firstplain, pvec)
ecinfo	*eci;
int		firstpos;
int		firstplain;
int		*pvec;
{
	int		x,y;

	firstpos = MODMASK & firstpos;
	firstplain = CHARMASK & firstplain;

	x = eci->scipher[firstpos];
	y = MODMASK & (firstplain + firstpos);

	return(decode_wire(eci, x, y, pvec));
}


/* Fill in the pvec with the characters decoded from assuming
 * that the permutation for this block maps x to y and vice-versa.
 * Return the number of characters added to pvec not counting
 * the termination character (NONE) that we always add (but not if
 * we return ERROR).
 * If any of the characers decoded to non-ascii values, then
 * return ERROR (a negative number).
 * Also return ERROR if the guess would conflict with the ones already
 * in eci->perm.
 * Also return ERROR if x == y.
 */
int	decode_wire(eci, x, y, pvec)
ecinfo	*eci;
int		x;
int		y;
int		*pvec;
{
	decode_wire_but(eci, x, y, pvec, NONE, NONE);
}


/* Fill in the pvec with the characters decoded from assuming
 * that the permutation for this block maps x to y and vice-versa.
 * Return the number of characters added to pvec not counting
 * the termination character (NONE) that we always add (but not if
 * we return ERROR).
 * If any of the characers decoded to non-ascii values, then
 * return ERROR (a negative number).
 * Also return ERROR if the guess would conflict with the ones already
 * in eci->perm.
 * Also return ERROR if x == y.
 * DO NOT include any characters in the postions ranging from
 * first to last inclusive.
 */
int	decode_wire_but(eci, x, y, pvec, first, last)
ecinfo	*eci;
int		x;
int		y;
int		*pvec;
int		first, last;
{
	int		delta;
	int		pos, firstflag;
	int		c,i;
	int		firstpos;
	int		otherpos;
	int		pvecindex;


	pvecindex = 0;
	pvec[pvecindex] = NONE;
	x = x & MODMASK;
	y = y & MODMASK;
	if (first > last)  {
		printf("\ndecode_wire_but called with first > last.\n");
		exit(0);
		}

	if (perm_conflict(eci->perm,x,y)  ||  x == y) {
#if DEBUG
		printf("CANNOT accept the guess of %d wired to %d.\n",
				x, y);
#endif
		return(ERROR);
		}

	firstpos = eci->permmap[x];
	if (firstpos != NONE) {
		delta = y - x;
		for_pos_in_class(pos, firstpos) {
			if (first <= pos && pos <= last)  continue;
			c = MODMASK & (eci->scipher[pos] + delta - pos);
			if (c != (c & CHARMASK))  return(ERROR);
			pvec[pvecindex++] = c;
			}
		}

	otherpos = eci->permmap[y];
	if (otherpos != NONE) {
		delta = x - y;
		for_pos_in_class(pos, otherpos) {
			if (first <= pos && pos <= last)  continue;
			c = MODMASK & (eci->scipher[pos] + delta - pos);
			if (c != (c & CHARMASK))  return(ERROR);
			pvec[pvecindex++] = c;
			}
		}

	pvec[pvecindex] = NONE;
	return(pvecindex);
}



/* Fill in an interger buffer from the characters of a byte buffer.
 * The buffers must have equal lengths.
 */
char2buf(cptr, iptr, length)
char	*cptr;
int		*iptr;
int		length;
{
	int		i;

	for (i = 0 ; i < length ; i++)  {
		*iptr++ = MODMASK & (*cptr++);
		}
}


/* Fill in a character buffer from the integers of a byte buffer.
 * If the integer value is NONE, use nonechar instead.
 * The buffers must have equal lengths.
 */
buf2char(cptr, iptr, length, nonechar)
char	*cptr;
int		*iptr;
int		length;
int		nonechar;
{
	int		i;

	for (i = 0 ; i < length ; i++)  {
		if (*iptr != NONE)  {
			*cptr++ = MODMASK & (*iptr++);
			}
		else {
			*cptr++ = nonechar;
			}
		}
}



/* Fill in an interger vector with the characters from a null
 * terminated string.  The interger vector is terminated by the
 * value NONE.
 */
str2pvec(cptr, iptr)
char	*cptr;
int	*iptr;
{
	while (*iptr++ = (MODMASK & *cptr++));
	*(--iptr) = NONE;
}


/* Fill in a null terminated string with the integers from a NONE
 * terminated vector.
 */
pvec2str(cptr, iptr)
char	*cptr;
int		*iptr;
{
	while (*iptr != NONE)  {
		*cptr++ = (MODMASK & *iptr++);
		}
	*cptr = 0;
}


/* Print a pvec on a stream.
 */
print_pvec(out, pvec)
FILE	*out;
int		*pvec;
{
	int		i,c;

	i = 0;
	while (*pvec != NONE)  {
		c = *pvec++;
		if (i++ % 20 == 0) fprintf(out,"\n");
		write_char(out, c);
		}
	fprintf(out,"\n");
}


/* Returns number of wires added to permvec assuming
 * that plaintext str occurs at pos.
 * Fills in permvec.  Returns -1 if conflict.
 * Note that the last entry in permvec is marked by x == -1.
 * The permvec will not have duplicates and will not conflict
 * with the perm specified by eci->perm.
 */
int		permvec_from_string(eci, str, pos, permvec)
ecinfo	*eci;
char	*str;
int		pos;
perment	permvec[];
{
	int		wcount;
	int		i, c, tmp;
	int		x,y;
	char	*cp;
	int		curpos;

	if (pos < 0 || pos >= BLOCKSIZE)  {return(ERROR);}

	wcount = 0;
	curpos = pos;
	cp = str;
	while ((c = (*cp & MODMASK)) != 0  &&  (curpos < BLOCKSIZE))  {
		x = eci->scipher[curpos];
		y = MODMASK & (c + curpos);
		if (perm_conflict(eci->perm, x, y))  {
			permvec[0].x = NONE;
			return(ERROR);
			}
		for (i = 0 ; i < wcount ; i++) {
			if ( (permvec[i].x == x  &&  permvec[i].y != y)
			  || (permvec[i].x == y  &&  permvec[i].y != x)
			  || (permvec[i].y == x  &&  permvec[i].x != y)
			  || (permvec[i].y == y  &&  permvec[i].x != x) )  {
#if DEBUG
				printf("Conflict within permvec.\n");
#endif
				permvec[0].x = NONE;
				return(ERROR);
				}
			if ( (permvec[i].x == x  &&  permvec[i].y == y)
			  || (permvec[i].x == y  &&  permvec[i].y == x) )
			    break;
			}
		permvec[i].x = x;
		permvec[i].y = y;
		if (i >= wcount)  wcount++;
	 	curpos++;
		cp++;
		}

	permvec[wcount].x = NONE;
	return(wcount);
}



/* Copy routine for permvecs.
 */
permvec_copy(from, to, maxnum)
perment	from[];
perment	to[];
int		maxnum;
{
	int		i;

	for (i = 0 ; i < maxnum ; i++)  {
		to[i] = from[i];
		if (from[i].x == NONE) break;
		}
}


/* Copy routine for pvecs.
 */
pvec_copy(from, to, maxnum)
int		from[];
int		to[];
int		maxnum;
{
	int		i;

	for (i = 0 ; i < maxnum ; i++)  {
		to[i] = from[i];
		if (from[i] == NONE) break;
		}
}



/* Fills in pvec with the plaintext characters deduced
 * from the wires in permvec that are not in the positions
 * ranging from butfirst to butlast.  Returns -1 if any
 * non-ascii chars are deduced, else count of chars.
 */
int		permvec2pvec(eci, permvec, pvec, butfirst, butlast)
ecinfo	*eci;
perment	permvec[];
int		pvec[];
int		butfirst;
int		butlast;
{	int		i, x, y;
	int		ccount;
	int		added;

	ccount = 0;

	for (i = 0 ; permvec[i].x != NONE ; i++)  {
		if (ccount >= BLOCKSIZE-1) break;
		x = permvec[i].x;
		y = permvec[i].y;
		added = decode_wire_but(eci, x, y, &(pvec[ccount]), butfirst, butlast);
		if (added < 0)  {
#if DEBUG
			printf("permvec wire decodes to non-ascii.\n");
#endif
			pvec[0] = -1;
			return(ERROR);
			}
		ccount += added;
		}
	pvec[ccount] = -1;
	return(ccount);
}

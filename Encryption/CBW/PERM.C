/*
 * Abstraction for the table of cipher text blocks and
 * their decoded permutations so far.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"specs.h"


#define	NPERLINE	10		/* How many values per line in save file. */
#define	FROMSTART	0		/* For fseek call, how offset measured. */


/* Input file name for permutations. */
char	*permfile;


/* Global state. */
int		permchgflg = FALSE;	/* True if perms changed since last save. */
int		*permtab[NPERMS];	/* Table of saved permutations or null. */
int		perminit = FALSE;	/* Initialization flag. */


/* Allocate and clear a permutation.
 */
int	*permalloc()
{
	int		i;
	int		*perm;

	perm = ((int *) malloc((BLOCKSIZE+1)*sizeof(int)));
	if (perm == NULL)  {
		printf("\nNo room to allocate permutation.\n");
		exit(0);
		}

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		perm[i] = -1;
		}

	return(perm);
}


/* Return a pointer (for read or write use) to the permutation
 * for the given block number.
 * Return NULL if the block number is bad.
 */
int	*refperm(blocknum)
int	blocknum;
{
	int		i;

	if ((blocknum < 0) || (NPERMS <= blocknum))  return(NULL);

	if (!perminit) {
		perminit = TRUE;
		for (i = 0 ; i < NPERMS ; i++)  permtab[i] = NULL;
		}

	if (permtab[blocknum] == NULL)  {
		permtab[blocknum] = permalloc();
		}

	return(permtab[blocknum]);
}


/* Save all the permutations in a file.
 * This can be invoked as a command.
 * For now, the are no arguments, the filename is fixed.
 * Return NULL if successful, else error mesage.
 * First the Zee matrix is dumped, then the permutations.
 * Each block is separated by a newline character.
 * Individual numbers are separated by blanks.
 */
char	*permsave(str)
char	*str;
{
	FILE	*fd;
	int		i;

	if ((fd = fopen(permfile, "w")) == NULL)  {
		sprintf(statmsg, "Could not open %s to write permutations.", permfile);
		return(statmsg);
		}

	storezee(fd);
	
	for (i = 0 ; i < NPERMS ; i++) {
		writeperm(fd, refperm(i));
		}

	fclose(fd);
	permchgflg = FALSE;
	return(NULL);
}


/* Restore all the permutations by reading them from a file.
 * This can be invoked as a command.
 * For now, the are no arguments, the filename is fixed.
 * Return NULL if successful, else ptr to error message.
 * Also call dblock to update its display.
 */
char	*permload(str)
char	*str;
{
	FILE	*fd;
	int		i;

	if ((fd = fopen(permfile, "r")) == NULL)  {
		sprintf(statmsg, "Could not open %s to read permutations.", permfile);
		return(statmsg);
		}

	loadzee(fd);

	for (i = 0 ; i < NPERMS ; i++) {
		readperm(fd, refperm(i));
		}

	fclose(fd);
	permchgflg = FALSE;

	dbssetblk(&dbstore, dbsgetblk(&dbstore));	/* Update perm and cbuf. */

	return(NULL);

}



/* Compute a permutation raised to some power.
 */
expperm(srcperm, dstperm, power)
int	*srcperm, *dstperm;
int	power;
{
	int		i, k, v;

	for (i = 0 ; i < BLOCKSIZE ; i++) {
		v = i;
		for (k = 0 ; k < power ; k++) {
			v = srcperm[v];
			if (v == -1)  break;
			}
		dstperm[i] = v;
		}
}


/* Computer product of two permutations.
 */
multperm(left, right, result)
int		*left;
int		*right;
int		*result;
{
	int		i, v;

	for (i = 0 ; i < BLOCKSIZE ; i++) {
		v = right[i];
		if (v != -1)  v = left[v];
		result[i] = v;
		}
}


/* Write a permutation onto the given stream.
 */
writeperm(fd, perm)
FILE	*fd;
int		perm[];
{
	int		j;

	for (j = 0 ; j < BLOCKSIZE ; j++)  {
		fprintf(fd, "%3d ", perm[j]);
		if ((j+1)%NPERLINE == 0)  fprintf(fd,"\n");
		}

	fprintf(fd,"\n");
}



/* Copy a permutation to another buffer.
 */
copyperm(src, dst)
int		src[];
int		dst[];
{
	int		j;

	for (j = 0 ; j < BLOCKSIZE ; j++)  {
		dst[j] = src[j];
		}
}


/* Read a permutation from the given stream into the given buffer.
 */
readperm(fd, perm)
FILE	*fd;
int		perm[];
{
	int		j;

	for (j = 0 ; j < BLOCKSIZE ; j++)  {
		fscanf(fd, "%3d", &perm[j]);
		}

	fscanf(fd,"\n");
}


/* Return a count of the number of values in the permutation that
 * are not equal to -1.
 * Max value is 256.
 */
int	permcount(perm)
int		perm[];
{
	int		i;
	int		count;

	count = 0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (perm[i] != -1)  count++;
		}
	return(count);
}


/* Return a count of the number of wires in a symetric permutation.
 * Return -1 if the permutation is not its own inverse or 
 * if it has fixed points.
 * Max value is 128.
 */
int	permwcount(perm)
int		perm[];
{
	int		i,v;
	int		count;

	count = 0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		v = perm[i];
		if (v == -1) continue;
		if (perm[v] != i)  return(-1);		/* Not self inverse. */
		if (v == i)        return(-1);		/* Has fixed point. */
		if (i < v)   continue;				/* Count first instance. */
		count++;
		}
	return(count);
}

/*
 * Encryption/Decrytion program based on crypt but uses A0 and Zee
 * rather than Rotor and Reflector.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>


#define	BLOCKSIZE	256
#define	MODMASK		(BLOCKSIZE-1)
#define	FALSE		0
#define	TRUE		1


/* Global state. */

int		perm[BLOCKSIZE];	/* Current A permutation. */
int		nxtperm[BLOCKSIZE];	/* Next A permutation. */
int		zee[BLOCKSIZE];		/* Zee permutation. */
int		zeeinv[BLOCKSIZE];	/* Inverse of Zee permutation. */


char	*permfile = "zeecode.perm";


/* Do the deed.
 */
main()
{
	int	i;
	int	*curperm;
	FILE *fd;

	if ((fd = fopen(permfile, "r")) == NULL)  {
		printf("\nCould not open %s to read permutations.\n", permfile);
		exit(0);
		}

	readblock(fd, zee);
	for (i = 0 ; i < BLOCKSIZE ; i++)  zeeinv[zee[i]] = i;
	readblock(fd, perm);

	fclose(fd);

	while (doblock(perm))  {
		pgate(perm, nxtperm, zee, zeeinv);
		for (i = 0 ; i < BLOCKSIZE ; i++)  perm[i] = nxtperm[i];
		}
}


/* Compute the permutation after inperm using z and its inverse zi.
 * The result is placed in outperm.
 */
pgate(inperm, outperm, z, zi)
int	*inperm;
int	*outperm;
int	*z;
int	*zi;
{
	int		i,x,v;
	int		w;

	for (i = 0 ; i < BLOCKSIZE ; i++) {
		w = -1;
		x = z[i];
		if (x != -1) {
			v = inperm[x&MODMASK];
			if (v != -1)
				w = zi[v&MODMASK];
			}
		outperm[i] = w;
		}
}


/* Read character from stdin, encrypt them with the given permutation, p,
 * and write them to stdout.
 * Return FALSE if reach end of file.
 */
doblock(p)
int	p[];
{
	int		pos;
	int		sc;
	char	c;

	for (pos = 0 ; pos < BLOCKSIZE ; pos++) {
		if ((c=getchar()) == EOF)  return(FALSE);
		sc = p[MODMASK&(c+pos)];
		if (sc == -1)  {putchar('?');}
		else  {putchar(MODMASK & (sc - pos));}
		}
	return(TRUE);
}


/* Read a block of BLOCKSIZE integers into the given buffer from
 * the given stream.
 * The block is terminated by a newline character.
 */
readblock(fd, buf)
FILE	*fd;
int		buf[];
{
	int	i;

	for (i = 0 ; i < BLOCKSIZE ; i++) {
		if (fscanf(fd, "%3d ", &buf[i]) != 1)  {
			printf("\nReadblock error on i = %d\n", i);
			exit(0);
			}
		}
	if (fscanf(fd, "\n") != 0)  {
		printf("\nReadblock error on newline\n");
		exit(0);
		}
}

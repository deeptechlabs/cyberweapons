/*
 * Abstraction for the table of cipher text blocks.
 *
 * Robert W. Baldwin, December 1984.
 *
 * History:
 * 3/8/85	Bob Baldwin		Changed fname to cipherfile.
 * 1/13/85  Bob Baldwin		Permutation stuff moved to perm.c
 */


#include	<stdio.h>
#include	"window.h"
#include	"layout.h"
#include	"specs.h"



#define	FROMSTART	0		/* For fseek call, how offset measured. */


/* Input file name for ciphertext, set by main. */
char	*cipherfile;


/* Fill the given buffer with the i-th ciphertext block.
 * The block index is zero-based.
 * Return FALSE if try to read non-existant bytes.
 */
int	fillcbuf(blocknum, cbuf)
int		blocknum;
char	*cbuf;
{
	FILE	*fd;
	long	offset;
	long	res;
	int		i;

	if ((blocknum < 0) || (NPERMS <= blocknum))  return(FALSE);

	if ((fd = fopen(cipherfile, "r")) == NULL)  {
		printf("\nCould not open %s to read ciphertext.\n", cipherfile);
		exit(0);
		}

	offset = blocknum * BLOCKSIZE;
	fseek(fd, offset, FROMSTART);
	res = ftell(fd);
	if (res != offset) {
		printf("\nSeek failed on %s to %d, got %d.\n", cipherfile, offset,res);
		exit(0);
		}

	if (fread(cbuf,sizeof(*(cbuf)),BLOCKSIZE,fd) != BLOCKSIZE)  {
		return(FALSE);
		}

	fclose(fd);

	return(TRUE);
}

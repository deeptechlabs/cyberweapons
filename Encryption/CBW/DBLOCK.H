extern	int	dbsrc2pos();
extern	int	dbsp2row();
extern	int	dbsp2col();
extern	int	dbsdpchar();



#define dbsinfo	struct xdbsinfo
struct	xdbsinfo	{
		char	*cbuf;		/* Ciphertext block. */
		int		*pbuf;		/* Plaintext block. */
		int		*perm;		/* Partial permutation, -1 -> none known. */
		char	*mbuf;		/* Bools for which chars are marked. */
		int		wirecnt;	/* Number of known wires in perm. */
		int		cmdloc;		/* Position in pbuf where cmd started. */
		int		cmdnext;	/* Index for next char to add to cmdbuf. */
		int		*cmdbuf;	/* Command from user. */
		int		*operm;		/* Permutation after last command. */
		int		blknum;		/* Zero based index of current block. */
		};

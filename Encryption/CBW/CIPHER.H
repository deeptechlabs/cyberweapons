
/*
 * Declarations for the information about a block.
 */


#define	SZMAX	 100	/* Number of classes in ecinfo table. */
#define	NCLASSES 256	/* Max number of classes of characters in a block. */


/* Macros */

/* Iterate of the positions in a class.
 * class is the index of one of the members of an equivalence class.
 * pos is a loop variable assigned to the positions in a class
 * starting with the value of class.
 * Both eci->next and firstflag must be bound in the calling environment.
 * firstflag is just an integer used as a flag, so it does not need to be
 * initialized.  eci->next must be a table of next pointers for this block.
 */
#define	for_pos_in_class(pos, class)  \
		for ((pos=class)&(firstflag=TRUE) ; \
			 firstflag || pos != class ; \
			 (firstflag=FALSE)&(pos = eci->next[pos]))


/* Return TRUE if given wiring conflicts with the wiring
 * in the given permutation.
 */
#define	perm_conflict(perm,x,y) \
		( ! perm_no_conflict(perm,x,y))

#define perm_no_conflict(perm,x,y) \
		(   (x != y) \
		 && (   ((perm)[x] == NONE  &&  (perm)[y] == NONE) \
		     || ((perm)[x] == y     &&  (perm)[y] == x)  ))


/* Structure Declarations */


/* Used for tables of unique permutation wirings. */
#define	perment	struct xperment
perment {
		int	x;		/* Sorted so x < y. */
		int	y;		/* x can be NONE. */
		};

#define	clinfo	struct	clinfox
clinfo	{
		short	nchars;		/* Number of chars in class. */
		short	npairs;		/* Cur num of chars next to ones in this class. */
		short	used;		/* True if class has an accepted value. */
		short	changed;	/* True if best value might have changed. */
		short	firstpos;	/* Position of first char of this class. */
		};

#define	adjinfo	struct	adjinfox
adjinfo	{
		short	left;		/* Index of class to the left (or NONE). */
		short	right;		/* Index of class to the right (or NONE). */
		};


#define	ecsize	struct ecsizex
ecsize	{
		int	size;		/* Size of class. */
		int	firstpos;	/* Index of first member. */
		};


#define	ecinfo	struct	ecinfox
ecinfo	{
		/* Index of next free spot in sizelist. */
		int	sizelast;
		
		/* Minimum size of class to put in sizelist. */
		int	sizemin;
		
		/* Table of all the classes sorted largest first. */
		ecsize	sizelist[SZMAX+1];
		
		/* Original ciphertext. */
		char	ciphertext[BLOCKSIZE+1];
		
		/* Cipher chars shifted by  their index. */
		int	scipher[BLOCKSIZE+1];
		
		/* Next[i] is a circular list of the positions of all the */
		/* members of the class that contains ith cipher char. */
		int	next[BLOCKSIZE+1];
		
		/* Position of first member of the class influenced by perm[i]. */
		int	permmap[BLOCKSIZE+1];
		/* Decipher permutation. A  -1 indicated unknown wiring. */
		
		/* This is cumulative. */
		int	perm[BLOCKSIZE+1];
		
		/* Cumulative chars deciphered. */
		int	plaintext[BLOCKSIZE+1];
		
		/* Index in classlist to put net class. */
		int	nclasses;
		
		/* List of classes of characters. */
		clinfo	classlist[NCLASSES];
		
		/* Table mapping positions into their class list index. */
		short	posclass[BLOCKSIZE+1];
		};


/* The gsinfo structure is used to hold information about both
 * guessed at characters and known characters.  Both are needed to
 * compute scores based on letter pairs.
 */

#define	gsinfo	struct	gsinfox
gsinfo	{
		/* Ptr to a plaintext block of accepted chars. */
		int	*cknown;
		
		/* Ptr to a plaintext block of guessed at chars. */
		int	*cguessed;
		
		/* Vector of positions within cguessed that have characters. */
		/* The list is terminated by -1. */
		int	cpos[SZMAX+1];
		};


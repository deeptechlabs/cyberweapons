#include	<stdio.h>
#include	<signal.h>
#include	<setjmp.h>

/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 * Additional restrictions due to national laws governing the use, import or
 * export of cryptographic software is the responsibility of the software user,
 * importer or exporter to follow.
 *
 *					     _
 *					Stig Ostholm
 *					Department of Computer Engineering
 *					Chalmers University of Technology
 */

/*
 * compile
 *
 *	Generates site specific information
 *
 */

#ifdef __STDC__
# define VOID (void)
#else
# define VOID
#endif

typedef int (sig_func)();


jmp_buf		sig_jmp;
static int	caught_signal = 0;

int	caught_sig()
{
	caught_signal = 1;
	longjmp(sig_jmp, 1);

	/* To keep some compilers happy */
	return 0;
}

main()
{
	unsigned long		l;
	unsigned char		c, cl[sizeof(l)], al[sizeof(l) * 2];
	register int		i;
	sig_func		*old_sig_func;


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");

	/*
	 * Number of bits in an unsigned char.
	 */
	for (c = 0x01, i = 0; c; c <<= 1, i++);
	if (i != 8) {
		fprintf(stderr, "unsigned char must be 8 bits\n");
		exit(1);
	} else {
		printf("#define UNSIGNED_CHAR_BITS %d\n\n", i);
	}
	printf("#define UNSIGNED_CHAR_MAX %d\n\n", (0x1 << i) - 1);

	/*
	 * Number of bits in an unsigned long.
	 */
	for (l = 0x01, i = 0; l; l <<= 1, i++);
	printf("#define UNSIGNED_LONG_BITS %d\n\n", i);

	/*
	 * Byte order in an unsigned long.
	 */
	cl[0] = 1;
	for (i = 1; i < sizeof(cl); i++)
		cl[i] = 0;
	l = *((unsigned long *) cl);
	if (l > 1) {
		printf("#define UNSIGNED_MSB_FIRST\n\n");
	} else {
		printf("#define UNSIGNED_LSB_FIRST\n\n");
	}

	/*
	 * Hardware specific definitions.
	 */
	/*
	 * Check if address alignment is necesry on unsigned long.
	 * This method does only work if a SIGBUS signal is generated
	 * when fetching an unsigned long from an unaligned address.
	 */

	for (i = 0; i < sizeof(al); i++)
		al[i] = i;

	old_sig_func = (sig_func *) signal(SIGBUS, caught_sig);
	if (!setjmp(sig_jmp))
		for (i = 0; i < sizeof(l); i++)
			l += *((unsigned long *) & al[i]);
	VOID signal(SIGBUS, old_sig_func);

	if (caught_signal) {
		printf("#define UNSIGNED_LONG_ALIGN\n\n");
		caught_signal = 0;
	}

	/*
	 * Compiler type specific defines.
	 *
	 * Is there any other simple way to ensure that a compiler
	 * knowns `void' ?
	 */
#ifdef AIX
	printf("#define _BSD\n");
#endif
#ifdef __STDC__
	printf("#define VOID (void)\n");
	printf("#define CONST const\n");
#else
	printf("#define VOID\n");
	printf("#define CONST\n");
#endif

	exit(0);
}

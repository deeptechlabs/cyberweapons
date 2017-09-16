/* Kappa: utility program
	Prints a table of character frequencies drawn from stdin.
;The table appears in natural order.
;Frequencies are per 1000 characters.
*/

# include <stdio.h>

long table[256];
long total;

main()
	{
;int ch;
	int i;
	int lcmpr();

	while ((ch = getchar()) != EOF) {
;;table[ch]++;
		total++;
		}
	printf("Total: %ld\n\n", total);
	for (i = 0; i < 256; i++) {
;;table[i] *= 1000;
		table[i] /= total;
		}
	for (i = 0; i < 256; i++) {
;;printf("%3.3ld ", table[i]);
		if ((i + 1) % 16 == 0) putchar('\n');
		if ((i + 1) % 128 == 0) putchar('\n');
		}
	}

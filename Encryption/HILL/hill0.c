# include <stdio.h>
# include "table.i"
# ifdef DOS
# include <fcntl.h>
# include <io.h>
# endif

# ifdef DOS
# define TTY "con"
# else
# define TTY "/dev/tty"
# endif

# define Over(x) for (x = 0; x < order; x++)
# define Times(a,b) ((long)(a) * (long)(b) % 257)

int mode;

char key[256];
int matkey[16][16];
int invec[16];
int outvec[16];
int order;


setup(argc, argv)
int argc; char **argv;
	{
	FILE *tty;

	if (strcmp(argv[1], "-e") == 0)
		mode = 'e';
	else if (strcmp(argv[1], "-d") == 0)
		mode = 'd';
	else {
		fprintf(stderr, "usage: hill -e [key]\n   or: hill -d [key]\n");
		exit(1);
		}
	if (argc > 2)
		strcpy(key, argv[2]);
	else {
		tty = fopen(TTY, "r+");
		setbuf(tty, NULL);
		fprintf(tty, "Key? ");
		fgets(key, sizeof(key), tty);
		key[strlen(key) - 1] = 0;
		fclose(tty);
		}
	}

makemat()
	{
	int i, j, k;
	int n = 0;
	FILE *tty;

	setorder();
	Over(i) Over(j)
		matkey[i][j] = key[n++];
	for (i = 0; i < strlen(key); i++)
		key[i] = 0;
	square();
	while ((k = invert()) != EOF)
		matkey[k][k] = (matkey[k][k] + 1) % 257;
	}

setorder()
	{
	int n = strlen(key);

	for (order = 0; order < 17; order++)
		if (order*order > n) break;
	order--;
	if (order < 3) {
		fprintf(stderr, "key size < 9\n");
		exit(1);
		}
	}

square()
	{
	int result[16][16];
	int i, j, k;

	Over(i) Over(j)
		result[i][j] = 0;
	Over(i) Over(j) Over(k)
		result[i][j] += Times(matkey[i][k], matkey[k][j]);
	Over(i) Over(j)
		matkey[i][j] = result[i][j] % 257;
	}

int invert()
	{
	int matrix[16][16];
	int inverse[16][16];
	int i, j, k;
	int t;
	int pivot;

	Over(i) Over(j) {
		matrix[i][j] = matkey[i][j];
		inverse[i][j] = 0;
		}
	Over(k)
		inverse[k][k] = 1;

	Over(k) {
		if (matrix[k][k] == 0) {
			for (i = k + 1; i < order; i++)
				if (matrix[i][k]) {
					Over(j) {
						t = matrix[i][j];
						matrix[i][j] = matrix[k][j];
						matrix[k][j] = t;
						t = inverse[i][j];
						inverse[i][j] = inverse[k][j];
						inverse[k][j] = t;
						}
					break;
					}
			if (i == order) return(k);
			}

		pivot = inverses[matrix[k][k]];
		Over(j) {
			matrix[k][j] = Times(matrix[k][j], pivot);
			inverse[k][j] = Times(inverse[k][j], pivot);
			}
		Over(i) if (i != k) {
			pivot = matrix[i][k];
			Over(j) {
				matrix[i][j] -= Times(pivot, matrix[k][j]);
				if (matrix[i][j] < 0) matrix[i][j] += 257;
				inverse[i][j] -= Times(pivot, inverse[k][j]);
				if (inverse[i][j] < 0) inverse[i][j] += 257;
				}
			}
		}

	if (mode == 'd') Over(i) Over(j)
		matkey[i][j] = inverse[i][j];
	return(EOF);
	}


int getvec()
	{
	int i;
	int padf = 0;

	Over(i)
		if ((invec[i] = getchar()) == EOF) {
			if (i == 0) return(0);
			else if (padf) invec[i] = rand() % 257;
			else { invec[i] = 256; padf++; }
			}
		else if (invec[i] == 255 && mode == 'd')
			invec[i] += getchar();
	return(i);
	}

putvec()
	{
	int j;

	Over(j)
		switch(outvec[j]) {
		case 256:
			if (mode == 'd') return;
			else putchar(255), putchar(1);
			break;
		case 255:
			putchar(255);
			if (mode == 'e') putchar(0);
			break;
		default:
			putchar(outvec[j]);
			}
	}

matmul()
	{
	int i, j, k;

	Over(i) {
		outvec[i] = 0;
		Over(j)
			outvec[i] += Times(invec[j], matkey[i][j]);
		outvec[i] %= 257;
		}
	}

main(argc, argv)
int argc; char **argv;
	{
	long tloc;

# ifdef DOS
;setmode(fileno(stdin), O_BINARY);
	setmode(fileno(stdout), O_BINARY);
# endif
	time(&tloc);
	srand((int) tloc);
	setup(argc, argv);
	makemat();
	while(getvec()) {
;	matmul();
;	putvec();
;;}
	}

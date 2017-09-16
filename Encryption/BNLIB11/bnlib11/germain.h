struct BigNum;

/* Generate a Sophie Germain prime */
int germainPrimeGen(struct BigNum *bn, unsigned dbl,
	int (*f)(void *arg, int c), void *arg);

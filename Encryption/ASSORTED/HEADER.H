/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

/* Random global constants that have to be defined */
#define TRUE 1
#define FALSE 0

#define ALPHABET_LEN 26

/* Constants used in one program only */
#define BLOCK_DEFAULT_CHARS_PER_BLOCK 5

#define KAPPA_DEF_MAXKEY 20
#define KAPPA_DEF_THRESHOLD 5.0

#define ROTOR_MAX_ROTORS 128
#define ROTOR_DEF_ROTORFILE "rotor.cfg"

/* Usage statements for each program */
#define BLOCK_USAGE "Usage: %s [-c <chars/block>] [-b <blocks/line>]\n"
#define CAESAR_USAGE "Usage: %s [-d] [-k] <key>\n"
#define CAPITAL_USAGE "Usage: %s [-l]\n"
#define CHI_SQ_USAGE "Usage: %s [-e] [-2] [-3]\n"
#define ENTROPY_USAGE "Usage: %s [-e] [-2] [-3]\n"
#define KAPPA_USAGE "Usage:%s [-m <maximum>] [-t <threshold>]\n"
#define N_GRAM_USAGE "Usage: %s [-e | -p] [-s] [-d] [-t]\n"
#define ROTOR_USAGE \
"Usage: %s [-d] [-k] <key> [-f <rotor file>] [-r <rotor order>]\n"
#define TEXTSTRP_USAGE "Usage: %s [-p] [-a [-r Xtext [-r...] ] ]\n"
#define VIGENERE_USAGE "Usage: %s [-d] [-k] key\n"

/* Useful macros */
#define alpha_len2 (alpha_len * alpha_len)
#define alpha_len3 (alpha_len2 * alpha_len)

double log10(double);
#define log2(X) (log10((X)) / log10(2))

#define l2n(X) (toupper(X) - 'A')
#define n2l(X) ((X) + 'A')

#define memory_error() die("Could not allocate necessary memory", -173)
#define file_open_error() die("Could not open a file (but which one?)", -171)
#define file_format_error() die("file format incorrect (but which one?)", -167)

#define usage(X) fprintf(stderr, X, argv[0]); fprintf(stderr, \
"To redirect IO use [-i <input name>] and [-o <output name>]\n"); exit(-2)
#define print_error(X) fprintf(stderr, "%s", X)
#define error(X) print_error("ERROR: "); print_error(X); print_error("\n")
#define die(X,Y) error(X); exit(Y)

/* function declarations for tyhe functions in separate files */
int getopt(int, char **, char *);
char * get_key(char *);

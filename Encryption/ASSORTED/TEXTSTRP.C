/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

/*
  strip out non-alphabetic characters, replacing them with an ascii
  description if so desired.

  This isn't exactly the most elegant way to write this, but it gets
  the job done.
  */

#include "header.h"

static char * initial_replacements[] = {
    "!", "Bang",		/* 0, 1 */
     "\"", "DoubleQuote",
     "#", "Hash",
     "$", "Dollar",
     "%", "Percent",
     "&", "Ampersand",		/* 10,11 */
     "'", "SingleQuote",
     "(", "OpenParen",
     ")", "CloseParen",
     "*", "Splat",
     "+", "Plus",		/* 20,21 */
     ",", "Comma",
     "-", "Dash",
     ".", "Period",
     "/", "Slash",
     "0", "Zero",		/* 30,31 */
     "1", "One",
     "2", "Two",
     "3", "Three",
     "4", "Four",
     "5", "Five",		/* 40,41 */
     "6", "Six",
     "7", "Seven",
     "8", "Eight",
     "9", "Nine",
     ":", "Colon",		/* 50,51 */
     ";", "Semicolon",
     "<", "LessThan",
     "=", "Equal",
     ">", "GreaterThan",
     "?", "QuestionMark",	/* 60,61 */
     "@", "At",
     "[", "OpenBracket",
     "\\", "Backslash",
     "]", "CloseBracket",
     "^", "Circumflex",		/* 70,71 */
     "_", "Underscore",
     "`", "Backquote",
     "{", "OpenBrace",
     "|", "Pipe",
     "}", "CloseBrace",		/* 80,81 */
     "~", "Tilde"		/* 82,83 */
};

int main(int argc, char * argv[])
{
    char c;
    int z;
    extern int opterr;
    extern char *optarg;
    int errflg = 0;
    int use_alpha= FALSE;
    int just_display = FALSE;
    char replacements[128][128];

    for (z = 0; z < 128; z++) {
	*(replacements[z]) = '\0';
    }
    for (z = 0; z <= 83; z = z + 2) {
	c = *(initial_replacements[z]);
	strcpy(replacements[(int)c], initial_replacements[z + 1]);
    }
    
    opterr = 0;
    while ((z = getopt(argc, argv, "apr:i:o:")) != EOF) {
	switch ((char)z) {
	case 'i':
	    if (freopen(optarg, "r", stdin) == NULL) {
		file_open_error();
	    }
	    break;
	case 'o':
	    if (freopen(optarg, "w", stdout) == NULL) {
		file_open_error();
	    }
	    break;
	case 'a':
	    use_alpha = TRUE;
	    break;
	case 'p':
	    just_display = TRUE;
	    break;
	case 'r':
	    strcpy(replacements[(int)optarg[0]], (optarg + 1));
	    break;
	case '?':
	    errflg = TRUE;
	}
    }
    if (errflg) {
	usage(TEXTSTRP_USAGE);
    }

    if (just_display) {
	for (z = 0; z <= 127; z++) {
	    if (*(replacements[z]) != '\0') {
		printf("%3d %c: %s\n", z, (char)z, replacements[z]);
	    }
	}
	return(0);
    }
    
    while ((z = getchar()) != EOF) {
	c = (char)z;
	if (isalpha(c)) {
	    putchar(c);
	} else if (use_alpha) {
	    printf("%s", replacements[(int)c]);
	}
    } 
    return(0);
}

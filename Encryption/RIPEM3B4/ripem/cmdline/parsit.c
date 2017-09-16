/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*
 * Parse a string of words separated by spaces into an
 * array of pointers to characters, just like good ol' argv[]
 * and argc.
 *
 * Usage:
 *
 * char line[132];
 * char **argv;
 * int argc;
 *
 *  argv = (char **) NULL;
 *  argc = parsit(line, &argv);
 *
 * returns the number of words parsed in argc.  argv[argc] will
 * be (char *) NULL to indicate end of list, if you're not
 * happy with just knowing how many words you have.
 *
 * Note that setting argv = (char **) NULL is only done the first
 * time the routine is called with a new "argv" -- it tells
 * parsit that "argv" is a new array, and parsit shouldn't free
 * up the elements (as it would do if it were an old array).
 *
 *  Phil Lapsley
 *  College of Engineering
 *  University of California, Berkeley
 *  (ARPA: phil@Berkeley.ARPA; UUCP: ...!ucbvax!phil)
 */

#include <stdio.h>
#include "parsitpr.h"
#include <stdlib.h>
#include <string.h>

int
parsit(line, array)
char *line;
char ***array;
{
  char  **argv;
  char  *word;
  char  *linecp;
  int i, j, num_words,longest_word;

  argv = *array;
  if (argv != (char **) NULL) {  /* Check to see if we should */
    for (i = 0; argv[i] != (char *) NULL; i++)  /* free */
      free(argv[i]);  /* the old array */
    free((char *) argv);  /* and then free the ptr itself */
  }
  
  linecp = line;
  num_words = longest_word = 0;
  while (1) { /* count words in input */
    for (; *linecp == ' ' || *linecp == '\t'; ++linecp)
      ;
    if (*linecp == '\0')
      break;
    word = linecp;
    for (; *linecp != ' ' && *linecp != '\t' && *linecp != '\0'; ++linecp)
      ;
    ++num_words;
    if ((i = (int)(linecp - word)) > longest_word) longest_word = i;
    if (*linecp == '\0')
      break;
  }

  /* Then malloc enough for that many words plus 1 (for null) */

  if ((argv = (char **) malloc((num_words + 1) * sizeof(char *))) ==
      (char **) NULL) {
    fprintf(stderr, "parsit: malloc out of space!\n");
    return(0);
  }
  /* malloc enough the longest word */
  
  if ((word = (char *) malloc(longest_word+1)) == (char *) NULL) {
    fprintf(stderr, "parsit: malloc out of space!\n");
    return(0);
  }

  j = i = 0;
  while (1) { /* Now build the list of words */
    for (; *line == ' ' || *line == '\t'; ++line)
      ;
    if (*line == '\0')
      break;
    
    i = 0;
    for (; *line != ' ' && *line != '\t' && *line != '\0'; ++line)
      word[i++] =  *line;
    word[i] = '\0';
    argv[j] = malloc(strlen(word) + 1);
    if (argv[j] == (char *) NULL) {
      fprintf(stderr, "parsit: malloc out of space!\n");
      free(word);
      return(0);
    }

    (void) strcpy(argv[j], word);
    ++j;
    if (*line == '\0')
      break;
  }
  argv[j] = (char *) NULL;  /* remember null at end of list */
  *array = argv;
  free(word);
  return(j);
}

#include <stdio.h>
#include "hut-include.h"

extern char	*alo_getpass();

char *
hut_read_password(prompt,verify)

char	*prompt;
int	verify;

{
  char	*p1,*p2;
  int	again;
  int	n;

  p1 = 0;
  p2 = 0;
  again = 1;
  n = 10;
  while (again) {
    if (p1) free(p1);
    if (p2) free(p2);
    if (!(p1 = hut_getpass(prompt)))
      return 0;
    if (verify) {
      if (!(p2 = hut_getpass("Verify: "))) {
	free(p1);
	return 0;
      }
      if (strcmp(p1,p2)) {
	n--;
	if (n <= 0) {
	  fprintf(stderr,"Too many mismatches\n");
	  if (p1) free(p1);
	  if (p2) free(p2);
	  return 0;
	} else {
	  fprintf(stderr,"Mismatch\n");
	}
      } else {
	again = 0;
      }
    } else {
      again = 0;
    }
  }
  if (p2) free(p2);
  return p1;
}

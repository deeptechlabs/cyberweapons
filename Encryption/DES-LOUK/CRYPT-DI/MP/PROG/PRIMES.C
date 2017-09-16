#include <stdio.h>

extern char	*malloc();

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  char	*a;
  int	m;
  int	i,j;

  m = atoi(argv[1]);

  a = malloc(m);
  bzero(a,m);

  for(i = 3; i < m; i += 2) {
    if (!a[i]) {
      printf("%d\n",i);
      fflush(stdout);
      for(j = i; j <  m; j += i) {
	a[j] = 1;
      }
    }
  }
  return 0;
}

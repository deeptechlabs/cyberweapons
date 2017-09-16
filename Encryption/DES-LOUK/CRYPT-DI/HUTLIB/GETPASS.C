#include <sys/types.h>
#include <sys/file.h>
#ifdef SYSV
#include <fcntl.h>
#include <termio.h>
#else
#include <sgtty.h>
#endif
#include <stdio.h>
#include "hut-include.h"

char *
hut_getpass(prompt)

char	*prompt;

{
#ifdef SYSV
  struct termio t_old;
#else
  struct sgttyb	t_old;
#endif
  FILE		*tf;
  int		tf0;
  FILE		*of = stderr;
  int		ef;
  char		*r;
  hut_linebuf	lb = hut_linebuf_z;
  
  if ((tf0 = open("/dev/tty",O_RDWR,0)) != -1) {
    if (!(tf = fdopen(tf0,"r"))) {
      close(tf0);
      return 0;
    }
  } else {
    tf = 0;
  }
  if (!tf)
    tf = stdin;
  fputs(prompt,of);
  fflush(of);
#ifdef SYSV
  ioctl(fileno(tf), TCGETA, &t_old);
  ef = t_old.c_lflag & ECHO;
  t_old.c_lflag &= ~ECHO;
  ioctl(fileno(tf),TCSETAF,&t_old);
#else
  ioctl(fileno(tf),TIOCGETP,&t_old);
  ef = t_old.sg_flags & ECHO;
  t_old.sg_flags &= ~ECHO;
  ioctl(fileno(tf),TIOCSETP,&t_old);
#endif
  r = hut_getline(tf,&lb);
  if (r)
    fputs("\n",of);
#ifdef SYSV
  ioctl(fileno(tf),TCGETA,&t_old);
  t_old.c_lflag &= ~ECHO;
  t_old.c_lflag |= ef;
  ioctl(fileno(tf),TCSETA,&t_old);
#else
  ioctl(fileno(tf),TIOCGETP,&t_old);
  t_old.sg_flags &= ~ECHO;
  t_old.sg_flags |= ef;
  ioctl(fileno(tf),TIOCSETP,&t_old);
#endif
  if (tf != stdin)
    fclose(tf);
  return r;
}

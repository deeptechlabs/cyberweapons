#include <string.h>
#include <fcntl.h>

#ifndef BSD		/* System V */
#include <sys/ioctl.h>
#include <termio.h>

#define GETMODES	TCGETA
#define	SETMODES	TCSETA
#define	TTYFLAGS	c_lflag
#define	MODETYPE	termio
#endif

#ifdef BSD
#include <sgtty.h>

#define GETMODES	TIOCGETP
#define	SETMODES	TIOCSETN
#define	TTYFLAGS	sg_flags 
#define	MODETYPE	sgttyb
#endif

#ifndef MSDOS
#include <signal.h>

int setEcho(fd, echo)
   int fd;
   int echo;
{  
   struct MODETYPE modes;
   int res, oldecho;

   res = ioctl(fd, GETMODES, &modes);
   oldecho = modes.TTYFLAGS & ECHO;
   if (echo >= 0) {
      if (echo) {
	 modes.TTYFLAGS |= ECHO;
      } else {
	 modes.TTYFLAGS &= ~ECHO;
      }
      res = ioctl(fd, SETMODES, &modes);
   }
   return oldecho;
}

static void (*oldSigInt)();
static int  oldEcho = 1;			/* assume echo was on */
static int  fd = -1;

void intHandler()
{
   setEcho(fd, oldEcho);			/* restore echoing */
   close(fd);					/* close /dev/tty */
   (void) signal(SIGINT, oldSigInt);		/* restore old handler */
   kill(getpid(), SIGINT);			/* invoke old handler */
}

/*
 * A machine dependent function to prompt for and read a keystring from stdin
 *
 * Input:
 *   prompt - A string output to display prior to requesting input
 *   str    - where to put the characters
 *   size   - the number of storage locations reserved for the key
 *    
 * Returns: 
 *    The number of characters read (not counting terminating '\n')
 *
 * Reads in upto <size> characters from the terminal.  Terminated by EOF
 * or '\n'.  String will be '\0' terminated if its less than size bytes.
 */
int getkey(prompt, str, size)
   char *prompt;
   char *str;
   register unsigned size;
{
   int count, len;
   char buf[1], *chp = str;;

   fd = open("/dev/tty", O_RDWR);
   if (fd < 0) return fd;
   oldSigInt = signal(SIGINT, intHandler);
   oldEcho = setEcho(fd, 0);		/* disable printing of input */

   len   = strlen(prompt);
   count = write(fd, prompt, len);

   if (size != 0) do {
      count = read(fd, buf, 1);
      if (count != 1) break;
      if (buf[0] == '\n') break;
      *chp++ = buf[0];
   } while (--size != 0);
 
   if (size != 0) {
      *chp = '\0';
   }
   write(fd, "\n", 1);			/* goto next line */
   setEcho(fd, oldEcho);		/* restore echo to previous state */
   (void) signal(SIGINT, oldSigInt);
   close(fd);
   return chp - str;
}
#endif

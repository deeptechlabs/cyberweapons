#include <stdio.h>
#include <signal.h>

char *
getpass(prompt)
char *prompt;
{
	register char *p;
	register c;
	static char pbuf[128];

	fprintf(stderr, "%s", prompt); fflush(stderr);
	for (p=pbuf; (c = getc(stderr))!='\n' && c!=EOF;) {
		if (p < &pbuf[127])
			*p++ = c;
	}
	*p = '\0';
	fprintf(stderr, "\n"); fflush(stderr);
	return(pbuf);
}

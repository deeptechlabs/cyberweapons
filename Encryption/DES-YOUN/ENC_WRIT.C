/* des_enc_write */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include <errno.h>
#include "des_local.h"

int des_enc_write(fd,buf,len,sched,iv)
int fd;
char *buf;
int len;
des_key_schedule sched;
des_cblock *iv;
	{
	long l,rnum;
	int i,j,k;
	char outbuf[BSIZE];
	char shortbuf[8];
	char *p;
	static int start=1;

	/* If we are sending less than 8 bytes, the same char will look
	 * the same if we don't pad it out with random bytes */
	if (start)
		{
		start=0;
		srandom(time(NULL));
		}

	/* lets recurse if we want to send the data in small chunks */
	if (len > MAXWRITE)
		{
		j=0;
		for (i=0; i<len; i+=k)
			{
			k=des_enc_write(fd,&(buf[i]),
				((len-i) > MAXWRITE)?MAXWRITE:(len-i),sched,iv);
			if (k < 0)
				return(k);
			else
				j+=k;
			}
		return(j);
		}

	/* pad short strings */
	if (len < 8)
		{
		p=shortbuf;
		bcopy(buf,shortbuf,len);
		for (i=len; i<8; i++)
			shortbuf[i]=random();
		rnum=8;
		}
	else
		{
		p=buf;
		rnum=((len+7)/8*8); /* round up to nearest eight */
		}

	/* write length first */
	l=htonl(len);
	bcopy(&l,outbuf,sizeof(long));
	if (des_rw_mode == DES_PCBC_MODE)
		pcbc_encrypt((des_cblock *)p,(des_cblock *)&(outbuf[4]),
			(long)((len<8)?8:len),sched,iv,DES_ENCRYPT); 
	else
		cbc_encrypt((des_cblock *)p,(des_cblock *)&(outbuf[4]),
			(long)((len<8)?8:len),sched,iv,DES_ENCRYPT); 

	/* output */
	for (j=0; j<rnum+4; j+=i)
		{
		i=write(fd,outbuf,(int)(rnum+4));
		if (i == -1)
			{
			if (errno == EINTR)
				i=0;
			else 	/* This is really a bad error - very bad
				 * It will stuff-up both ends. */
				return(-1);
			}
		}

	return(len);
	}

/* speed.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

#ifndef MSDOS
#define TIMES
#endif

#include <stdio.h>
#include <signal.h>
#ifndef VMS
#include <time.h>
#include <sys/types.h>
#ifdef TIMES
#include <sys/times.h>
#endif /* TIMES */
#else /* VMS */
#include <types.h>
struct tms {
	time_t tms_utime;
	time_t tms_stime;
	time_t tms_uchild;          /* I dunno...  */
	time_t tms_uchildsys;       /* so these names are a guess :-) */
	}
#endif
#ifndef TIMES
#include <sys/timeb.h>
#endif
#include "des.h"

/* The following if from times(3) man page.  It may need to be changed */
#ifndef CLK_TCK
#ifndef VMS
#define HZ	60.0
#else /* VMS */
#define HZ	100.0
#endif
#else /* CLK_TCK */
#define HZ ((double)CLK_TCK)
#endif

#define BUFSIZE	((long)1024*8)
long run=0;

#ifdef SIGALRM
#ifdef __STDC__
#define SIGRETTYPE void
#else
#define SIGRETTYPE int
#endif 

SIGRETTYPE sig_done(sig)
int sig;
	{
	signal(SIGALRM,sig_done);
	run=0;
	}
#endif

#define START	0
#define STOP	1

double Time_F(s)
int s;
	{
	double ret;
#ifdef TIMES
	static struct tms tstart,tend;

	if (s == START)
		{
		times(&tstart);
		return(0);
		}
	else
		{
		times(&tend);
		ret=((double)(tend.tms_utime-tstart.tms_utime))/HZ;
		return((ret == 0.0)?1e-6:ret);
		}
#else /* !times() */
	static struct timeb tstart,tend;
	long i;

	if (s == START)
		{
		ftime(&tstart);
		return(0);
		}
	else
		{
		ftime(&tend);
		i=(long)tend.millitm-(long)tstart.millitm;
		ret=((double)(tend.time-tstart.time))+((double)i)/1000.0;
		return((ret == 0.0)?1e-6:ret);
		}
#endif
	}

main(argc,argv)
int argc;
char *argv[];
	{
	long count;
	FILE *in,*out,*std;
	static unsigned char buf[BUFSIZE];
	static des_cblock key={0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
	des_key_schedule sch;
	int i,j,k,enc,catfd;
	double d,a,b,c;
	long ca,cb,cc,cd;

#ifndef TIMES
	printf("To get the most acurate results, try to run this\n");
	printf("program when this computer is idle.\n");
#endif

#ifndef SIGALRM
	printf("First calculate aprox speed...\n");
	des_set_key(key,sch);
	count=10;
	do	{
		count*=2;
		Time_F(START);
		for (i=count; i; i--)
			des_ecb_encrypt(buf,buf,&(sch[0]),DES_ENCRYPT);
		d=Time_F(STOP);
		} while (d <3);
	ca=count;
	cb=count*10;
	cc=count*10*8/BUFSIZE+1;
	cd=count/20+1;
	printf("Doing set_key's %ld times\n",ca);
#define COND(d)	(count != (d))
#define COUNT(d) (d)
#else
#define COND(c)	(run)
#define COUNT(d) (count)
	signal(SIGALRM,sig_done);
	printf("Doing set_key for 60 seconds\n");
	alarm(60);
#endif

	Time_F(START);
	for (count=0,run=1; COND(ca); count++)
		des_set_key(key,sch);
	d=Time_F(STOP);
	printf("%ld set_key's in %.2f seconds\n",count,d);
	a=((double)COUNT(ca))/d;

#ifdef SIGALRM
	printf("Doing des_ecb_encrypt's for 60 seconds\n");
	alarm(60);
#else
	printf("Doing %ld des_ecb_encrypt's\n",cb);
#endif
	Time_F(START);
	for (count=0,run=1; COND(cb); count++)
		des_ecb_encrypt(buf,buf,&(sch[0]),DES_ENCRYPT);
	d=Time_F(STOP);
	printf("%ld des_ecb_encrypt's in %.2f second\n",count,d);
	b=((double)COUNT(cb)*8)/d;

#ifdef SIGALRM
	printf("Doing des_cbc_encrypt on %ld byte blocks for 60 seconds\n",
		BUFSIZE);
	alarm(60);
#else
	printf("Doing %ld des_cbc_encrypt's on %ld byte blocks\n",cc,BUFSIZE);
#endif
	Time_F(START);
	for (count=0,run=1; COND(cc); count++)
		des_cbc_encrypt(buf,buf,BUFSIZE,&(sch[0]),
		&(key[0]),DES_ENCRYPT);
	d=Time_F(STOP);
	printf("%ld des_cbc_encrypt's of %ld byte blocks in %.2f second\n",
		count,BUFSIZE,d);
	c=((double)COUNT(cc)*BUFSIZE)/d;

#ifdef SIGALRM
	printf("Doing crypt for 60 seconds\n");
	alarm(60);
#else
	printf("Doing %ld crypt's\n",cd);
#endif
	Time_F(START);
	for (count=0,run=1; COND(cd); count++)
		crypt("testing1","ef");
	d=Time_F(STOP);
	printf("%ld crypts in %.2f second\n",count,d);
	d=((double)COUNT(cd))/d;

	printf("set_key       per sec = %12.2f (%5.1fuS)\n",a,1.0e6/a);
	printf("DES ecb bytes per sec = %12.2f (%5.1fuS)\n",b,8.0e6/b);
	printf("DES cbc bytes per sec = %12.2f (%5.1fuS)\n",c,8.0e6/c);
	printf("crypt         per sec = %12.2f (%5.1fuS)\n",d,1.0e6/d);
	}

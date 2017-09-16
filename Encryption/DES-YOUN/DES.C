/* des.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include <stdio.h>
#ifdef VMS
#include <types.h>
#include <stat.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include "des.h"

#if defined(__STDC__) || defined(VMS) || defined(M_XENIX) || defined(MSDOS)
#include <string.h>
#define bcopy(f,t,n)	memcpy(t,f,(size_t)(n))
#define bzero(s,n)	memset(s,0,(size_t)(n))
#define bcmp(a,b,n)	memcmp(a, b,(size_t)(n))
#define index(s,c)	strchr(s,c)
#endif

#ifdef MSDOS
/* Turbo C v 2.0 feof(FILE *) only works in text mode. :-(. */
#define feof(a)	((num == 0) || (num != BUFSIZE))
#endif

#define BUFSIZE (8*1024)
#define VERIFY  1
#define KEYSIZ	8
#define KEYSIZB 1024 /* should hit tty line limit first :-) */
char key[KEYSIZB+1];
int encrypt,longk=0;
char *in=NULL,*out=NULL;
FILE *DES_IN,*DES_OUT;

int eflag,dflag,kflag,bflag,fflag,sflag,error;

main(argc,argv)
int argc;
char *argv[];
	{
	int i;
	struct stat ins,outs;

	eflag=dflag=kflag=bflag=fflag=sflag=0,error=0;
	bzero(key,sizeof(key));

	for (i=1; i<argc; i++)
		{
		if ((argv[i][0] == '-') && (argv[i][1] != '\0') &&
			(argv[i][2] == '\0'))
			{
			switch (argv[i][1])
				{
			case 'e':
				eflag=1;
				break;
			case 'E':
				eflag=1;
				longk=1;
				break;
			case 'd':
				dflag=1;
				break;
			case 'D':
				dflag=1;
				longk=1;
				break;
			case 'b':
				bflag=1;
				break;
			case 'f':
				fflag=1;
				break;
			case 's':
				sflag=1;
				break;
			case 'k':
				kflag=1;
				if ((i+1) == argc)
					{
					fputs("must have a key with the -k option\n",stderr);
					error=1;
					}
				else
					{
					int j;

					i++;
					strncpy(key,argv[i],KEYSIZB);
					for (j=strlen(argv[i])-1; j>=0; j--)
						argv[i][j]='\0';
					}
				break;
			default:
				fprintf(stderr,"'%s' unknown flag\n",argv[i]);
				error=1;
				break;
				}
			}
		else
			{
			if (in == NULL)
				in=argv[i];
			else if (out == NULL)
				out=argv[i];
			else
				error=1;
			}
		}
	if (error) usage();
	if ((eflag+dflag) == 1)
		{
		if (eflag) encrypt=DES_ENCRYPT;
		if (dflag) encrypt=DES_DECRYPT;
		}
	else
		usage();

	if (	(in != NULL) &&
		(out != NULL) &&
#ifndef MSDOS
		(stat(in,&ins) != -1) &&
		(stat(out,&outs) != -1) &&
		(ins.st_dev == outs.st_dev) &&
		(ins.st_ino == outs.st_ino))
#else /* MSDOS */
		(strcmp(in,out) == 0))
#endif
			{
			fputs("input and output file are the same\n",stderr);
			exit(3);
			}

	if (!kflag)
		if (des_read_pw_string(key,KEYSIZB+1,"Enter key:",eflag?VERIFY:0))
			{
			fputs("password error\n",stderr);
			exit(2);
			}

	if (in == NULL)
		DES_IN=stdin;
	else if ((DES_IN=fopen(in,"r")) == NULL)
		{
		perror("opening input file");
		exit(4);
		}

	if (out == NULL)
		DES_OUT=stdout;
	else if ((DES_OUT=fopen(out,"w")) == NULL)
		{
		perror("opening output file");
		exit(5);
		}

#ifdef MSDOS
	/* This should set the file to binary mode. */
	{
#include <fcntl.h>
	setmode(fileno(DES_IN),O_BINARY);
	setmode(fileno(DES_OUT),O_BINARY);
	}
#endif

	doencryption();
	fclose(DES_IN);
	fclose(DES_OUT);
	exit(0);
	}

usage()
	{
	fputs("des (-e|-E) | (-d|-D) [ -bfs ] [ -k key ] [ input-file [ output-file]\n",
		stderr);
	exit(1);
	}

doencryption()
	{
	static char buf[BUFSIZE+8];
	static char obuf[BUFSIZE+8];
	des_key_schedule ks;
	char iv[8];
	int num=0,i,j,k,l,ll,last,ex=0;
	des_cblock kk;

	if (longk)
		{
		des_string_to_key(key,kk);
		}
	else
		for (i=0; i<KEYSIZ; i++)
			{
			l=0;
			k=key[i];
			for (j=0; j<8; j++)
				{
				if (k&1) l++;
				k>>=1;
				}
			if (l & 1)
				kk[i]=key[i]&0x7f;
			else
				kk[i]=key[i]|0x80;
			}

	des_set_key(kk,ks);
	bzero(key,sizeof(key));
	bzero(kk,sizeof(kk));
	/* woops - A bug that does not showup under unix :-( */
	bzero(iv,sizeof(iv));

	l=1;
	/* first read */
	if (encrypt == DES_ENCRYPT)
		{
		for (;;)
			{
			num=l=fread(buf,1,BUFSIZE,DES_IN);
			if (l < 0)
				{
				perror("read error");
				exit(6);
				}

			if (feof(DES_IN))
				{
				last=l%8;
				srand(time(NULL));
				for (i=7-last; i>0; i--)
					buf[l++]=rand()&0xff;
				buf[l++]=last;
				ex=1;
				}

			if (bflag)
				for (i=0; i<l; i+=8)
					des_ecb_encrypt(
						(des_cblock *)&(buf[i]),
						(des_cblock *)&(obuf[i]),
						ks,encrypt);
			else
				{
				des_cbc_encrypt(
					(des_cblock *)buf,(des_cblock *)obuf,
					(long)l,ks,(des_cblock *)iv,encrypt);
				if (l >= 8) bcopy(&(obuf[l-8]),iv,8);
				}

			i=0;
			while (i != l)
				{
				j=fwrite(obuf,1,l-i,DES_OUT);
				if (j == -1)
					{
					perror("Write error");
					exit(7);
					}
				i+=j;
				}
			if (feof(DES_IN)) break;
			}
		}
	else /* decrypt */
		{
		ex=1;
		for (;;)
			{
			if (ex) {
				l=fread(buf,1,BUFSIZE,DES_IN);
				ex=0;
				}
			if (l < 0)
				{
				perror("read error");
				exit(6);
				}

			if (bflag)
				for (i=0; i<l; i+=8)
					des_ecb_encrypt(
						(des_cblock *)&(buf[i]),
						(des_cblock *)&(obuf[i]),
						ks,encrypt);
			else
				{
				des_cbc_encrypt(
					(des_cblock *)buf,(des_cblock *)obuf,
				 	(long)l,ks,(des_cblock *)iv,encrypt);
				if (l >= 8) bcopy(&(buf[l-8]),iv,8);
				}

			ll=fread(buf,1,BUFSIZE,DES_IN);
			if (feof(DES_IN) && (ll == 0))
				{
				last=obuf[l-1];
				if ((last > 7) || (last < 0))
					{
					fputs("The file was not decrypted correctly.\n",
						stderr);
					exit(8);
					}
				l=l-8+last;
				}
			i=0;
			while (i != l)
				{
				j=fwrite(obuf,1,l-i,DES_OUT);
				if (j == -1)
					{
					perror("Write error");
					exit(7);
					}
				i+=j;
				}
			l=ll;
			if ((l == 0) && feof(DES_IN)) break;
			}
		}
	}

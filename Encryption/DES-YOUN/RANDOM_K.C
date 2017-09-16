/* random_key.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include "des_local.h"

int des_random_key(ret)
des_cblock ret;
	{
	des_key_schedule ks;
	static ulong c=0;
	static ushort pid=0;
	static des_cblock data={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	des_cblock key;

#ifdef MSDOS
	pid=1;
#else
	if (!pid) pid=getpid();
#endif
	((ulong *)key)[0]=(ulong)time(NULL);
	((ulong *)key)[1]=(ulong)((pid)|((c++)<<16));

	des_set_odd_parity((des_cblock *)data);
	des_set_key((des_cblock *)data,ks);
	des_cbc_cksum((des_cblock *)key,(des_cblock *)key,
		(long)sizeof(key),ks,(des_cblock *)data);
	des_set_odd_parity((des_cblock *)key);
	des_cbc_cksum((des_cblock *)key,(des_cblock *)key,
		(long)sizeof(key),ks,(des_cblock *)data);

	bcopy(key,ret,sizeof(key));
	bzero(key,sizeof(key));
	bzero(ks,sizeof(ks));
	return(0);
	}

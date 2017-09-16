/* string_to_key.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include "des_local.h"

int des_string_to_key(str,key)
char *str;
des_cblock *key;
	{
	des_key_schedule ks;
	int i,length;
	register uchar j;

	bzero(key,8);
	length=strlen(str);
#ifdef OLD_STR_TO_KEY
	for (i=0; i<length; i++)
		(*key)[i%8]^=(str[i]<<1);
#else /* MIT COMPATIBLE */
	for (i=0; i<length; i++)
		{
		j=str[i];
		if ((i%16) < 8)
			(*key)[i%8]^=(j<<1);
		else
			{
			/* Reverse the bit order 05/05/92 eay */
			j=((j<<4)&0xf0)|((j>>4)&0x0f);
			j=((j<<2)&0xcc)|((j>>2)&0x33);
			j=((j<<1)&0xaa)|((j>>1)&0x55);
			(*key)[7-(i%8)]^=j;
			}
		}
#endif
	des_set_odd_parity((des_cblock *)key);
	des_set_key((des_cblock *)key,ks);
	des_cbc_cksum((des_cblock *)str,(des_cblock *)key,(long)length,ks,
		(des_cblock *)key);
	bzero(ks,sizeof(ks));
	des_set_odd_parity(key);
	return(0);
	}

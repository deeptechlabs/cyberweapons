/* rpw.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include <stdio.h>
#include "des.h"

main()
	{
	des_cblock k;
	int i;

	printf("read passwd\n");
	if ((i=des_read_password(k,"Enter password:",0)) == 0)
		{
		printf("password = ");
		for (i=0; i<8; i++)
			printf("%02x ",k[i]);
		}
	else
		printf("error %d\n",i);
	printf("\n");
	printf("read passwd and verify\n");
	if ((i=des_read_password(k,"Enter verified password:",1)) == 0)
		{
		printf("password = ");
		for (i=0; i<8; i++)
			printf("%02x ",k[i]);
		printf("\n");
		}
	else
		printf("error %d\n",i);
	}

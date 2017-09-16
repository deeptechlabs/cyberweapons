/* pcbc_encrypt.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include "des_local.h"

int des_pcbc_encrypt(input,output,length,schedule,ivec,encrypt)
des_cblock *input;
des_cblock *output;
long length;
des_key_schedule schedule;
des_cblock *ivec;
int encrypt;
	{
	register ulong sin0,sin1,xor0,xor1,tout0,tout1;
	ulong tin[2],tout[2];
	uchar *in,*out,*iv;

	in=(uchar *)input;
	out=(uchar *)output;
	iv=(uchar *)ivec;

	if (encrypt)
		{
		c2l(iv,xor0);
		c2l(iv,xor1);
		for (; length>0; length-=8)
			{
			if (length >= 8)
				{
				c2l(in,sin0);
				c2l(in,sin1);
				}
			else
				c2ln(in,sin0,sin1,length);
			tin[0]=sin0^xor0;
			tin[1]=sin1^xor1;
			des_encrypt((ulong *)tin,(ulong *)tout,
				schedule,encrypt);
			tout0=tout[0];
			tout1=tout[1];
			xor0=sin0^tout[0];
			xor1=sin1^tout[1];
			l2c(tout0,out);
			l2c(tout1,out);
			}
		}
	else
		{
		c2l(iv,xor0); c2l(iv,xor1);
		for (; length>0; length-=8)
			{
			c2l(in,sin0);
			c2l(in,sin1);
			tin[0]=sin0;
			tin[1]=sin1;
			des_encrypt((ulong *)tin,(ulong *)tout,
				schedule,encrypt);
			tout0=tout[0]^xor0;
			tout1=tout[1]^xor1;
			if (length >= 8)
				{
				l2c(tout0,out);
				l2c(tout1,out);
				}
			else
				l2cn(tout0,tout1,out,length);
			xor0=tout0^sin0;
			xor1=tout1^sin1;
			}
		}
	tin[0]=tin[1]=tout[0]=tout[1]=0;
	return(0);
	}

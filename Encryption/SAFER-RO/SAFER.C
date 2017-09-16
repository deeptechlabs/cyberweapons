From Mercury!cl.cam.ac.uk!Michael.Roe Thu Dec 22 12:34:27 1994
Return-Path: <Mercury!cl.cam.ac.uk!Michael.Roe>
Received: by chinet.chinet.com (/\==/\ Smail3.1.28.1 #28.1{chinet})
	id <m0rKsLL-0002AxC@chinet.chinet.com>; Thu, 22 Dec 94 12:34 CST
Received: by mercury.mcs.com (/\==/\ Smail3.1.28.1 #28.5)
	id <m0rKsCN-000BlKC@mercury.mcs.com>; Thu, 22 Dec 94 12:25 CST
Received: from ely.cl.cam.ac.uk (user mrr (rfc931)) by swan.cl.cam.ac.uk 
          with SMTP (PP-6.5) to cl; Thu, 22 Dec 1994 18:24:50 +0000
To: schneier@chinet.chinet.com (Bruce Schneier)
cc: Michael.Roe@cl.cam.ac.uk
Subject: SAFER-K64
Date: Thu, 22 Dec 1994 18:24:43 +0000
From: Mike Roe <Michael.Roe@cl.cam.ac.uk>
Message-ID: <"swan.cl.cam.:160850:941222182504"@cl.cam.ac.uk>
Status: RO



/* safer64-int.c - SAFER-K64 encryption algorithm */

#define ALG_OK 0
#define ALG_NOTOK -1

static unsigned char log[256];
static unsigned char exp[256];


int saferk64_preinit()
{
int i;
unsigned int power;

	power = 1;
	for (i=0;i<256;i++)
	{ 
    		exp[i] = power & 0xff;
    		log[power & 0xff] = i;
    		power = (power * 45) % 257;
  	}
  	exp[128] = 0;
  	log[0] = 128;

  	return (ALG_OK);
}

struct subkey {
	unsigned char octets[8];
};

struct keyschedule {
	struct subkey rounds[22];
};

#define PHT(a1, a2, b1, b2) \
	b2 = a1 + a2; \
	b1 = b2 + a1;

int saferk64_encrypt(ks, in, out)
unsigned char *in;
unsigned char *out;
struct keyschedule *ks;
{
unsigned char a1, a2, a3, a4, a5, a6, a7, a8;
unsigned char b1, b2, b3, b4, b5, b6, b7, b8;
int i;

	a1 = in[0];
	a2 = in[1];
	a3 = in[2];
	a4 = in[3];
	a5 = in[4];
	a6 = in[5];
	a7 = in[6];
	a8 = in[7];

	for (i=1;i<=6;i++)
	{
		a1 ^= ks->rounds[2*i-1].octets[0];
		a2 += ks->rounds[2*i-1].octets[1];
		a3 += ks->rounds[2*i-1].octets[2];
		a4 ^= ks->rounds[2*i-1].octets[3];
		a5 ^= ks->rounds[2*i-1].octets[4];
		a6 += ks->rounds[2*i-1].octets[5];
		a7 += ks->rounds[2*i-1].octets[6];
		a8 ^= ks->rounds[2*i-1].octets[7];

		b1 = exp[a1];
		b2 = log[a2];
		b3 = log[a3];
		b4 = exp[a4];
		b5 = exp[a5];
		b6 = log[a6];
		b7 = log[a7];
		b8 = exp[a8];

		b1 += ks->rounds[2*i].octets[0];
		b2 ^= ks->rounds[2*i].octets[1];
		b3 ^= ks->rounds[2*i].octets[2];
		b4 += ks->rounds[2*i].octets[3];
		b5 += ks->rounds[2*i].octets[4];
		b6 ^= ks->rounds[2*i].octets[5];
		b7 ^= ks->rounds[2*i].octets[6];
		b8 += ks->rounds[2*i].octets[7];

      		PHT(b1, b2, a1, a2);
      		PHT(b3, b4, a3, a4);
      		PHT(b5, b6, a5, a6);
      		PHT(b7, b8, a7, a8);

      		PHT(a1, a3, b1, b2);
      		PHT(a5, a7, b3, b4);
      		PHT(a2, a4, b5, b6);
      		PHT(a6, a8, b7, b8);

      		PHT(b1, b3, a1, a2);
      		PHT(b5, b7, a3, a4);
      		PHT(b2, b4, a5, a6);
      		PHT(b6, b8, a7, a8);

	}

	a1 ^= ks->rounds[2*6+1].octets[0];
	a2 += ks->rounds[2*6+1].octets[1];
	a3 += ks->rounds[2*6+1].octets[2];
	a4 ^= ks->rounds[2*6+1].octets[3];
	a5 ^= ks->rounds[2*6+1].octets[4];
	a6 += ks->rounds[2*6+1].octets[5];
	a7 += ks->rounds[2*6+1].octets[6];
	a8 ^= ks->rounds[2*6+1].octets[7];

	out[0] = a1;
	out[1] = a2;
	out[2] = a3;
	out[3] = a4;
	out[4] = a5;
	out[5] = a6;
	out[6] = a7;
	out[7] = a8;

	return (ALG_OK);
};

#define IPHT(a1, a2, b1, b2) \
	b1 = a1 - a2; \
	b2 = -b1 + a2;

int saferk64_decrypt(ks, in, out)
struct keyschedule *ks;
unsigned char *in;
unsigned char *out;
{
unsigned char a1, a2, a3, a4, a5, a6, a7, a8;
unsigned char b1, b2, b3, b4, b5, b6, b7, b8;
int i;

        a1 = in[0] ^ ks->rounds[2*6+1].octets[0];
        a2 = in[1] - ks->rounds[2*6+1].octets[1];
        a3 = in[2] - ks->rounds[2*6+1].octets[2];
        a4 = in[3] ^ ks->rounds[2*6+1].octets[3];
        a5 = in[4] ^ ks->rounds[2*6+1].octets[4];
        a6 = in[5] - ks->rounds[2*6+1].octets[5];
        a7 = in[6] - ks->rounds[2*6+1].octets[6];
        a8 = in[7] ^ ks->rounds[2*6+1].octets[7];

	for (i=6;i>=1;i--)
	{
        	IPHT(a7, a8, b6, b8);
        	IPHT(a5, a6, b2, b4);
        	IPHT(a3, a4, b5, b7);
        	IPHT(a1, a2, b1, b3);

        	IPHT(b7, b8, a6, a8);
        	IPHT(b5, b6, a2, a4);
        	IPHT(b3, b4, a5, a7);
        	IPHT(b1, b2, a1, a3);

        	IPHT(a7, a8, b7, b8);
        	IPHT(a5, a6, b5, b6);
        	IPHT(a3, a4, b3, b4);
       		IPHT(a1, a2, b1, b2);

		b1 -= ks->rounds[2*i].octets[0];
                b2 ^= ks->rounds[2*i].octets[1];
                b3 ^= ks->rounds[2*i].octets[2];
                b4 -= ks->rounds[2*i].octets[3];
                b5 -= ks->rounds[2*i].octets[4];
                b6 ^= ks->rounds[2*i].octets[5];
                b7 ^= ks->rounds[2*i].octets[6];
                b8 -= ks->rounds[2*i].octets[7];

		a1 = log[b1];
		a2 = exp[b2];
		a3 = exp[b3];
		a4 = log[b4];
		a5 = log[b5];
		a6 = exp[b6];
		a7 = exp[b7];
		a8 = log[b8];

                a1 ^= ks->rounds[2*i-1].octets[0];
                a2 -= ks->rounds[2*i-1].octets[1];
                a3 -= ks->rounds[2*i-1].octets[2];
                a4 ^= ks->rounds[2*i-1].octets[3];
                a5 ^= ks->rounds[2*i-1].octets[4];
                a6 -= ks->rounds[2*i-1].octets[5];
                a7 -= ks->rounds[2*i-1].octets[6];
                a8 ^= ks->rounds[2*i-1].octets[7];
	}

        out[0] = a1;
        out[1] = a2;
        out[2] = a3;
        out[3] = a4;
        out[4] = a5;
        out[5] = a6;
        out[6] = a7;
        out[7] = a8;

	return (ALG_OK);
};

		
int saferk64_init(key, out)
unsigned char *key;
struct keyschedule **out;
{
int i;
int j;
unsigned char buff[8];
struct keyschedule *ks;

	ks = (struct keyschedule *) calloc(1, sizeof(*ks));
	if (ks == (struct keyschedule *) 0)
		return (ALG_NOTOK);

	for (i=0;i<8;i++)
	{
		ks->rounds[1].octets[i] = key[i];
		buff[i] = key[i];
	}

	for (i=2;i<=2*6+1;i++)
	{
		for (j=0;j<8;j++)
		{
			buff[j] = (buff[j] << 3) | (buff[j] >> 5);
			ks->rounds[i].octets[j] = buff[j] + exp[exp[(9*i+j+1) & 0xff]];
		}
	}

	*out = ks;
	return (ALG_OK);
}

int saferk64_free(ks)
struct keyschedule *ks;
{
	free((char *) ks);
	return (ALG_OK);
}

/* end of file */


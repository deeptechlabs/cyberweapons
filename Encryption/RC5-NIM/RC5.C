From jnimmer@aol.com Mon Jan  2 23:52:04 CST 1995
Article: 28266 of sci.crypt
Path: chinet!pagesat.net!dfw.net!convex!cs.utexas.edu!howland.reston.ans.net!pipex!uunet!newstf01.news.aol.com!not-for-mail
From: jnimmer@aol.com (JNimmer)
Newsgroups: sci.crypt
Subject: Re: RC5 reference implementation
Date: 1 Jan 1995 16:34:47 -0500
Organization: America Online, Inc. (1-800-827-6364)
Lines: 76
Sender: root@newsbf02.news.aol.com
Message-ID: <3e775n$bmg@newsbf02.news.aol.com>
References: <3e74nc$qlo@vanbc.wimsey.com>
Reply-To: jnimmer@aol.com (JNimmer)

So therefore, for anyone interested, the code is:

#define ROTL(x,s) ((x)<<(s) | (x)>>(32-(s)))
#define ROTR(x,s) ((x)>>(s) | (x)<<(32-(s)))

#define ROUNDS 12
#define KR (2*(ROUNDS+1))

typedef unsigned long word32;

void RC5encrypt(word32 const in[2], word32 out[2], word32 key[KR])
{
 register word32 a, b;
 int i;

 a = in[0];
 b = in[1];

 a += *key++;
 b += *key++;

 for (i = 0; i < ROUNDS; i++) {
  a ^= b;
  a = ROTL(a, b&31) + *key++;

  b ^= a;
  b = ROTL(b, a&31);
  b += *key++;
 }
 
 out[0] = a;
 out[1] = b;
}


void RC5decrypt(word32 const in[2], word32 out[2], word32 key[KR])
{
 register word32 a, b;
 int i;

 a = in[0];
 b = in[1];

 key += KR;

 for (i = 0; i < ROUNDS; i++) {
  b -= *--key;
  b = ROTR(b, a&31) ^ a;

  a -= *--key;
  a = ROTR(a, b&31) ^ b;
 }

 b -= *--key;
 a -= *--key;

 out[0] = a;
 out[1] = b;
}

void main()
{
 word32 dat[2], enc[2], dec[2], ky[KR];

 int i;

 dat[0] = 0x12345678;
 dat[1] = 0x87654321;

 for(i=0;i<KR;i++)
  ky[i] = i;

 RC5encrypt(dat, enc, ky);
 RC5decrypt(enc, dec, ky);
}
-= remmiN ymereJ | Jeremy Nimmer =-



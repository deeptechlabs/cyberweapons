#include <stdio.h>
#include <stdlib.h>


#define R 8
#define ROOT 0x1f5U
#define ROTL(x, s) (((x) << (s)) | ((x) >> (32 - (s))))   
#define ROTR(x, s) (((x) >> (s)) | ((x) << (32 - (s))))   

#ifndef USUAL_TYPES
#define USUAL_TYPES
	typedef unsigned char	byte;	/*  8 bit */
	typedef unsigned short	word16;	/* 16 bit */
#ifdef __alpha
	typedef unsigned int	word32;	/* 32 bit */
#else  /* !__alpha */
	typedef unsigned long	word32;	/* 32 bit */
#endif /* ?__alpha */
#endif /* ?USUAL_TYPES */

#ifdef __alpha
#define O_FORMAT "0x%08xUL,%s"
#define T_FORMAT "0x%08xUL, "
#else  /* !__alpha */
#define O_FORMAT "0x%08lxUL,%s"
#define T_FORMAT "0x%08lxUL, "
#endif /* ?__alpha */
  
byte exptab[256], logtab[256];
byte offset[R];

byte mul(byte a, byte b)
/* multiply two elements of GF(2^m)
 */
{
   if (a && b) return exptab[(logtab[a] + logtab[b])%255];
   else return 0;
}

#define flip(w) \
{ \
	(w) = ((w) << 16) | ((w) >> 16); \
	(w) = (((w) << 8) & 0xff00ff00UL) | (((w) >> 8) & 0x00ff00ffUL); \
} /* flip */

void init()
/* produce logtab, exptab, and offset,
 * needed for multiplying in the field GF(2^m)
 * and/or in the key schedule
 */
{
   word16 i, j;
   exptab[0] = 1;
   for(i = 1; i < 256; i++) { 
      j = exptab[i-1] << 1;
      if (j & 0x100U) j ^= ROOT;
      exptab[i] = (byte)j;
      }
   logtab[0] = 0;
   for(i = 1; i < 255; i++)
      logtab[exptab[i]] = (byte)i;
   /* generate the offset values
    */
   offset[0] = 1;
   for(i = 1; i < R; i++) offset[i] = mul(2,offset[i-1]); 
}


static word32 T[256], D[256];

void main()
{
   FILE *out;
   byte ibox[256], g[9];
   byte in, u, t, pivot, tmp;
   byte box[256], G[4][4], iG[4][4], A[4][8];
   byte trans[9] = { 0xd6, 0x7b, 0x3d, 0x1f, 
                     0x0f, 0x05, 0x03, 0x01,
                     0xb1};
   word16 i, j, k;

   init();
   /* the substitution box based on F^{-1}(x)
    * + affine transform of the output
    */
   box[0] = 0;
   box[1] = 1;
   for(i = 2; i < 256; i++) 
      box[i] = exptab[255 - logtab[i]];
    
   for(i = 0; i < 256; i++) {
      in = box[i];
      box[i] = 0;
      for(t = 0; t < 8; t++) {
         u = in & trans[t];
         box[i] ^= ((1 & (u ^ (u >> 1) ^ (u >> 2) ^ (u >> 3) 
                  ^ (u >> 4) ^ (u >> 5) ^ (u >> 6) ^ (u >> 7)))
                   << (7 - t));
         }
      box[i] ^= trans[8];
      }
   
   /* diffusion box G
    * created by make_g.c
    */
   g[3] = 3;
   g[2] = 1;
   g[1] = 1;
   g[0] = 2;
    
   for(i = 0; i < 4; i++) 
      for(j = 0; j < 4; j++) 
         G[i][j] = g[(4 + j - i) % 4];
   
   for(i = 0; i < 4; i++) {
      for(j = 0; j < 4; j++) A[i][j] = G[i][j];
      for(j = 4; j < 8; j++) A[i][j] = 0;
      A[i][i+4] = 1;
      }
   for(i = 0; i < 4; i++) {
      pivot = A[i][i];
      if (pivot == 0) {
         t = i + 1;
         while ((A[t][i] == 0) && (t < 4)) t++;
         if (t == 4) fprintf(stderr,"noninvertible matrix G\n");
         else {
            for(j = 0; j < 8; j++) {
               tmp = A[i][j];
               A[i][j] = A[t][j];
               A[t][j] = tmp;
               }
            pivot = A[i][i];
            }
         }
      for(j = 0; j < 8; j++) 
         if (A[i][j])
            A[i][j] = exptab[(255 + logtab[A[i][j]] - logtab[pivot])%255];
      for(t = 0; t < 4; t++)
         if (i != t)
            {
            for(j = i+1; j < 8; j++)
               A[t][j] ^= mul(A[i][j],A[t][i]);
            A[t][i] = 0;
            }
      }
   for(i = 0; i < 4; i++)
      for(j = 0; j < 4; j++) iG[i][j] = A[i][j+4];
   
   
   /* output
    */
   out = fopen("square.tab","w");
   for(i = 0; i < 256; i++) ibox[box[i]] = (byte)i;
   
   fprintf(out,"static const byte Se[256] = {\n");
   for(i = 0; i < 16; i++) {
      for(j = 0; j < 16; j++) fprintf(out,"%3d, ",box[i*16+j]);
      fprintf(out,"\n");
      }
   fprintf(out,"};\n\n");
   fprintf(out,"static const byte Sd[256] = {\n");
   for(i = 0; i < 16; i++) {
      for(j = 0; j < 16; j++) fprintf(out,"%3d, ",ibox[i*16+j]);
      fprintf(out,"\n");
      }
   fprintf(out,"};\n\n");
   fprintf(out,"static const byte G[4][4] = {\n");
   for(i = 0; i < 4; i++) {
      for(k = 0; k < 4; k++) fprintf(out,"0x%02xU, ",G[i][k]);
      fprintf(out,"\n");
      }
   fprintf(out,"};\n\n");
   fprintf(out,"static const byte iG[4][4] = {\n");
   for(i = 0; i < 4; i++) {
      for(k = 0; k < 4; k++) fprintf(out,"0x%02xU, ",iG[i][k]);
      fprintf(out,"\n");
      }
   fprintf(out,"};\n\n");

   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         if (box[k]) 
			T[4*t+k] =
				((word32) mul(box[4*t+k],G[0][0]) << 24) ^
				((word32) mul(box[4*t+k],G[0][1]) << 16) ^
				((word32) mul(box[4*t+k],G[0][2]) <<  8) ^
				((word32) mul(box[4*t+k],G[0][3]));
         else
			T[4*t+k] = 0L;
         }
      }
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         if (ibox[k]) 
			D[4*t+k] =
				((word32) mul(ibox[4*t+k],iG[0][0]) << 24) ^
				((word32) mul(ibox[4*t+k],iG[0][1]) << 16) ^
				((word32) mul(ibox[4*t+k],iG[0][2]) <<  8) ^
				((word32) mul(ibox[4*t+k],iG[0][3]));
         else
			D[4*t+k] = 0L;
         }
      }

   fprintf(out,"static const byte logtab[256] = {\n");
   for(i = 0; i < 16; i++) {
      for(j = 0; j < 16; j++) fprintf(out,"%3u, ",logtab[i*16+j]);
      fprintf(out,"\n");
      }
   fprintf(out,"};\n\n");
   fprintf(out,"static const byte alogtab[256] = {\n");
   for(i = 0; i < 16; i++) {
      for(j = 0; j < 16; j++) fprintf(out,"%3u, ",exptab[(i*16+j)%255]);
      fprintf(out,"\n");
      }
   fprintf(out,"};\n\n");

   fprintf(out,"#ifdef LITTLE_ENDIAN\n\n");

   for(i = 0; i < 256; i++) {
	   flip(T[i]);
	   flip(D[i]);
   }

   fprintf(out,"static const word32 offset[R] = {\n");
   for(i = 0; i < R; i++) {
	   fprintf(out,O_FORMAT, (word32)(offset[i]), (i+1)%4 == 0? "\n" : " ");
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te0[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, T[4*t+k]);
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te1[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTL(T[4*t+k],  8));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te2[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTL(T[4*t+k], 16));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te3[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTL(T[4*t+k], 24));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td0[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, D[4*t+k]);
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td1[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTL(D[4*t+k],  8));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td2[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTL(D[4*t+k], 16));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td3[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTL(D[4*t+k], 24));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"#else  /* !LITTLE_ENDIAN */\n\n");

   for(i = 0; i < 256; i++) {
	   flip(T[i]);
	   flip(D[i]);
   }

   fprintf(out,"static const word32 offset[R] = {\n");
   for(i = 0; i < R; i++) {
	   fprintf(out,O_FORMAT, (word32)(offset[i]) << 24, (i+1)%4 == 0? "\n" : " ");
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te0[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, T[4*t+k]);
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te1[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTR(T[4*t+k],  8));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te2[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTR(T[4*t+k], 16));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Te3[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTR(T[4*t+k], 24));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td0[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, D[4*t+k]);
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td1[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTR(D[4*t+k],  8));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td2[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTR(D[4*t+k], 16));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"static const word32 Td3[256] = {\n");
   for(t = 0; t < 64; t++) {
      for(k = 0; k < 4; k++) {
         fprintf(out,T_FORMAT, ROTR(D[4*t+k], 24));
         }
      fprintf(out,"\n");   
      }
   fprintf(out,"};\n\n");

   fprintf(out,"#endif /* ?LITTLE_ENDIAN */\n");

   fclose(out);
   }

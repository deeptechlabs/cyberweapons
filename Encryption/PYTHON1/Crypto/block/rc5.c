
/*
 *  rc5.in : Implementation code for the RC5 block cipher
 *
 * Part of the Python Cryptography Toolkit, version 1.0.0
 *
 * Copyright (C) 1994, A.M. Kuchling
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */

#define MAXTABLE 100		/* Maximum size of S-box table; changing this
				   affects the maximum number of rounds
				   possible. */
typedef unsigned int U32;
#define LEFT(v,x,y,w,MASK)  {U32 t1=(y) % (w), t2,t3=x;\
		        t2=(w)-t1;\
		        v= ( (t3 << t1) & MASK) | \
   		           ( (t3 >> t2) & MASK);}
#define RIGHT(v,x,y,w,MASK)  {U32 t1=(y) % (w), t2,t3=x;\
		        t2=(w)-t1;\
		        v= ( (t3 >> t1) & MASK) | \
   		           ( (t3 << t2) & MASK);}



typedef struct 
{
  PCTObject_HEAD
  int version;			/* Version number of algorithm */
  int w;			/* Word size */
  int r;			/* Number of rounds */
  U32 S[MAXTABLE];
  U32 mask;
} RC5object;

static inline void
RC5init(self, key, keylen)
     RC5object *self;
     unsigned char *key;
     int keylen;
{
  unsigned int P, Q;
  int i;
  
  if (keylen<4 || keylen!=4+key[3])
    {
      PyErr_SetString(PyExc_ValueError,
		      "RC5: Bad key length");
      return;
    }
  if (key[0]!=0x10) 
    {
      PyErr_SetString(PyExc_ValueError,
		      "RC5: Bad RC5 algorithm version");
      return;
    }
  if (key[1]!=16 && key[1]!=32) 
    {
      PyErr_SetString(PyExc_ValueError,
		      "RC5: Unsupported word size");
      return;
    }
  self->version=key[0];
  self->w=key[1];
  self->r=key[2];

  switch(self->w)
    {
    case(16):
      P=0xb7e1; Q=0x9e37; self->mask=0xffff;
      break;
    case(32):
      P=0xb7e15163; Q=0x9e3779b9; self->mask=0xffffffff;
      break;
    }
  for(i=0; i<2*self->r+2; i++) self->S[i]=0;
  {
    unsigned int *L, A, B;
    int u=self->w/8, num;
    int j, t=2*(self->r+1), c=(keylen-5)/u;
    if ((keylen-5) % u) c++;
    L=malloc(sizeof(unsigned int)*c);
    if (L==NULL) 
      {
	PyErr_SetString(PyExc_MemoryError,
			"RC5: Can't allocate memory");
      }
    for(i=0; i<c; i++) L[i]=0;
    for(i=keylen-1-4; 0<=i; i--) L[i/u]=(L[i/u]<<8)+key[i+4];
    self->S[0]=P;
    for(i=1; i<t; i++) self->S[i]=(self->S[i-1]+Q) & self->mask;
    i=j=0;
    A=B=0;
    for(num = (t>c) ? 3*t : 3*c; 0<num; num--) 
      {
	LEFT(A, self->S[i]+A+B, 3, self->w, self->mask);
	self->S[i]=A;
	LEFT(B, L[j]+A+B, A+B, self->w, self->mask);
	L[j]=B;
	i=(i+1)%t;
	j=(j+1)%c;
      }
    free(L);
  }
}

static void RC5Encipher(self, Aptr, Bptr)
     RC5object *self;
     U32 *Aptr, *Bptr;
{
  int i;
  register U32 A, B;

  A=(*Aptr+self->S[0]) & self->mask;
  B=(*Bptr+self->S[1]) & self->mask;

  if (self->r)
  for (i=2; i<=2*self->r; i+=2) 
    {
      LEFT(A,A^B,B,self->w,self->mask);
      A += self->S[i];
      LEFT(B,A^B,A,self->w,self->mask);
      B += self->S[i+1];
    }
  *Aptr=A;
  *Bptr=B;
}

static void RC5Decipher(self, Aptr, Bptr)
     RC5object *self;
     unsigned int *Aptr, *Bptr;
{
  int i;
  U32 A, B;

  A=*Aptr;
  B=*Bptr;

  if (self->r)
  for (i=2*self->r; 2<=i; i-=2) 
    {
      RIGHT(B,B-self->S[i+1],A,self->w,self->mask);
      B ^= A;
      RIGHT(A,A-self->S[i],B,self->w,self->mask);
      A ^= B;
    }
  A = (A-self->S[0]) & self->mask;
  B = (B-self->S[1]) & self->mask;
  if (self->w==32) 
    {
      *Aptr=A;
      *Bptr=B;
    }
  else /* self->w==16 */
    {
      *Aptr=A;
      *Bptr=B;
    }
}

static inline void RC5encrypt(self, block)
     RC5object *self;
     unsigned char *block;
{
  U32 A,B;
  
  switch(self->w)
    {
    case (32):
      A=block[0] | block[1]<<8 | block[2]<<16 | block[3]<<24;
      B=block[4] | block[5]<<8 | block[6]<<16 | block[7]<<24;
      RC5Encipher(self, &A, &B);
      block[0]=A & 255; A>>=8;      
      block[1]=A & 255; A>>=8;      
      block[2]=A & 255; A>>=8;      
      block[3]=A; 
      block[4]=B & 255; B>>=8;      
      block[5]=B & 255; B>>=8;      
      block[6]=B & 255; B>>=8;      
      block[7]=B; 
      break;
    case (16):
      A=block[0] + block[1]*256;
      B=block[2] + block[3]*256;
      RC5Encipher(self, &A, &B);
      block[0] = A & 255; block[1] = A>>8;
      block[2] = B & 255; block[3] = B>>8;
      
      A=block[4] + block[5]*256;
      B=block[6] + block[7]*256;
      RC5Encipher(self, &A, &B);
      block[4] = A & 255; block[5] = A>>8; 
      block[6] = B & 255; block[7] = B>>8;
      break;
    }
}

static inline void RC5decrypt(self, block)
     RC5object *self;
     unsigned char *block;
{
  U32 A,B;
  
  switch(self->w)
    {
    case (32):
      A=block[0] | block[1]<<8 | block[2]<<16 | block[3]<<24;
      B=block[4] | block[5]<<8 | block[6]<<16 | block[7]<<24;
      RC5Decipher(self, &A, &B);
      block[0]=A & 255; A>>=8;      
      block[1]=A & 255; A>>=8;      
      block[2]=A & 255; A>>=8;      
      block[3]=A; 
      block[4]=B & 255; B>>=8;      
      block[5]=B & 255; B>>=8;      
      block[6]=B & 255; B>>=8;      
      block[7]=B; 
      break;
    case (16):
      A=block[0] + block[1]*256;
      B=block[2] + block[3]*256;
      RC5Decipher(self, &A, &B);
      block[0] = A & 255; block[1] = A>>8;
      block[2] = B & 255; block[3] = B>>8;
      
      A=block[4] + block[5]*256;
      B=block[6] + block[7]*256;
      RC5Decipher(self, &A, &B);
      block[4] = A & 255; block[5] = A>>8;
      block[6] = B & 255; block[7] = B>>8;
      break;
    }
}



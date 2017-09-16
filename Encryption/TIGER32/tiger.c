typedef unsigned long word32;
typedef unsigned char byte;

/* Big endian:                                         */
#if !(defined(__alpha)||defined(__i386__)||defined(__vax__))
#define BIG_ENDIAN
#endif

/* NOTE that this code is NOT FULLY OPTIMIZED for any  */
/* machine. Assembly code might be much faster on some */
/* machines, especially if the code is compiled with   */
/* gcc.                                                */

/* The number of passes of the hash function.          */
/* Three passes are recommended.                       */
/* Use four passes when you need extra security.       */
/* Must be at least three.                             */
#define PASSES 3

extern word32 table[4*256][2];

#define t1 (table)
#define t2 (table+256)
#define t3 (table+256*2)
#define t4 (table+256*3)

#define sub64(s0, s1, p0, p1) \
      temps0 = (p0); \
      tcarry = s0 < temps0; \
      s0 -= temps0; \
      s1 -= (p1) + tcarry;

#define add64(s0, s1, p0, p1) \
      temps0 = (p0); \
      s0 += temps0; \
      tcarry = s0 < temps0; \
      s1 += (p1) + tcarry;

#define xor64(s0, s1, p0, p1) \
      s0 ^= (p0); \
      s1 ^= (p1);

#define mul5(s0, s1) \
      tempt0 = s0<<2; \
      tempt1 = (s1<<2)|(s0>>30); \
      add64(s0, s1, tempt0, tempt1);

#define mul7(s0, s1) \
      tempt0 = s0<<3; \
      tempt1 = (s1<<3)|(s0>>29); \
      sub64(tempt0, tempt1, s0, s1); \
      s0 = tempt0; \
      s1 = tempt1;

#define mul9(s0, s1) \
      tempt0 = s0<<3; \
      tempt1 = (s1<<3)|(s0>>29); \
      add64(s0, s1, tempt0, tempt1);

#define save_abc \
      aa0 = a0; \
      aa1 = a1; \
      bb0 = b0; \
      bb1 = b1; \
      cc0 = c0; \
      cc1 = c1;

#define round(a0,a1,b0,b1,c0,c1,x0,x1,mul) \
      xor64(c0, c1, x0, x1); \
      temp0  = t1[((c0)>>(0*8))&0xFF][0] ; \
      temp1  = t1[((c0)>>(0*8))&0xFF][1] ; \
      temp0 ^= t2[((c0)>>(2*8))&0xFF][0] ; \
      temp1 ^= t2[((c0)>>(2*8))&0xFF][1] ; \
      temp0 ^= t3[((c1)>>(0*8))&0xFF][0] ; \
      temp1 ^= t3[((c1)>>(0*8))&0xFF][1] ; \
      temp0 ^= t4[((c1)>>(2*8))&0xFF][0] ; \
      temp1 ^= t4[((c1)>>(2*8))&0xFF][1] ; \
      sub64(a0, a1, temp0, temp1); \
      temp0  = t4[((c0)>>(1*8))&0xFF][0] ; \
      temp1  = t4[((c0)>>(1*8))&0xFF][1] ; \
      temp0 ^= t3[((c0)>>(3*8))&0xFF][0] ; \
      temp1 ^= t3[((c0)>>(3*8))&0xFF][1] ; \
      temp0 ^= t2[((c1)>>(1*8))&0xFF][0] ; \
      temp1 ^= t2[((c1)>>(1*8))&0xFF][1] ; \
      temp0 ^= t1[((c1)>>(3*8))&0xFF][0] ; \
      temp1 ^= t1[((c1)>>(3*8))&0xFF][1] ; \
      add64(b0, b1, temp0, temp1); \
      if((mul)==5) \
	{mul5(b0, b1);} \
      else \
	if((mul)==7) \
	  {mul7(b0, b1);} \
	else \
	  {mul9(b0, b1)};

#define pass(a0,a1,b0,b1,c0,c1,mul) \
      round(a0,a1,b0,b1,c0,c1,x00,x01,mul); \
      round(b0,b1,c0,c1,a0,a1,x10,x11,mul); \
      round(c0,c1,a0,a1,b0,b1,x20,x21,mul); \
      round(a0,a1,b0,b1,c0,c1,x30,x31,mul); \
      round(b0,b1,c0,c1,a0,a1,x40,x41,mul); \
      round(c0,c1,a0,a1,b0,b1,x50,x51,mul); \
      round(a0,a1,b0,b1,c0,c1,x60,x61,mul); \
      round(b0,b1,c0,c1,a0,a1,x70,x71,mul);

#define key_schedule \
      sub64(x00, x01, x70^0xA5A5A5A5, x71^0xA5A5A5A5); \
      xor64(x10, x11, x00, x01); \
      add64(x20, x21, x10, x11); \
      sub64(x30, x31, x20^((~x10)<<19), ~x21^(((x11)<<19)|((x10)>>13))); \
      xor64(x40, x41, x30, x31); \
      add64(x50, x51, x40, x41); \
      sub64(x60, x61, ~x50^(((x40)>>23)|((x41)<<9)), x51^((~x41)>>23)); \
      xor64(x70, x71, x60, x61); \
      add64(x00, x01, x70, x71); \
      sub64(x10, x11, x00^((~x70)<<19), ~x01^(((x71)<<19)|((x70)>>13))); \
      xor64(x20, x21, x10, x11); \
      add64(x30, x31, x20, x21); \
      sub64(x40, x41, ~x30^(((x20)>>23)|((x21)<<9)), x31^((~x21)>>23)); \
      xor64(x50, x51, x40, x41); \
      add64(x60, x61, x50, x51); \
      sub64(x70, x71, x60^0x89ABCDEF, x61^0x01234567);

#define feedforward \
      xor64(a0, a1, aa0, aa1); \
      sub64(b0, b1, bb0, bb1); \
      add64(c0, c1, cc0, cc1);

#ifdef UNROLL_COMPRESS
#define compress \
      save_abc \
      pass(a0,a1,b0,b1,c0,c1,5); \
      key_schedule; \
      pass(c0,c1,a0,a1,b0,b1,7); \
      key_schedule; \
      pass(b0,b1,c0,c1,a0,a1,9); \
      for(pass_no=3; pass_no<PASSES; pass_no++) { \
        key_schedule \
	pass(a0,a1,b0,b1,c0,c1,9); \
	tmpa=a0; a0=c0; c0=b0; b0=tmpa; \
	tmpa=a1; a1=c1; c1=b1; b1=tmpa;} \
      feedforward
#else
#define compress \
      save_abc \
      for(pass_no=0; pass_no<PASSES; pass_no++) { \
        if(pass_no != 0) {key_schedule} \
	pass(a0,a1,b0,b1,c0,c1,(pass_no==0?5:pass_no==1?7:9)) \
	tmpa=a0; a0=c0; c0=b0; b0=tmpa; \
	tmpa=a1; a1=c1; c1=b1; b1=tmpa;} \
      feedforward
#endif

#define tiger_compress_macro(str, state) \
{ \
  register word32 a0, a1, b0, b1, c0, c1, tmpa; \
  word32 aa0, aa1, bb0, bb1, cc0, cc1; \
  word32 x00, x01, x10, x11, x20, x21, x30, x31, \
         x40, x41, x50, x51, x60, x61, x70, x71; \
  register word32 temp0, temp1, tempt0, tempt1, temps0, tcarry; \
  word32 i; \
  int pass_no; \
\
  a0 = state[0]; \
  a1 = state[1]; \
  b0 = state[2]; \
  b1 = state[3]; \
  c0 = state[4]; \
  c1 = state[5]; \
\
  x00=str[0*2]; x01=str[0*2+1]; x10=str[1*2]; x11=str[1*2+1]; \
  x20=str[2*2]; x21=str[2*2+1]; x30=str[3*2]; x31=str[3*2+1]; \
  x40=str[4*2]; x41=str[4*2+1]; x50=str[5*2]; x51=str[5*2+1]; \
  x60=str[6*2]; x61=str[6*2+1]; x70=str[7*2]; x71=str[7*2+1]; \
\
  compress; \
\
  state[0] = a0; \
  state[1] = a1; \
  state[2] = b0; \
  state[3] = b1; \
  state[4] = c0; \
  state[5] = c1; \
}

#ifdef UNROLL_COMPRESS
/* The compress function is inlined */
#define tiger_compress(str, state) \
  tiger_compress_macro(((word32*)str), ((word32*)state))
#else
/* The compress function is a function */
tiger_compress(word32 *str, word32 state[6])
{
  tiger_compress_macro(((word32*)str), ((word32*)state));
}
#endif

tiger(word32 *str, word32 length, word32 res[6])
{
  register word32 i, j;
  byte temp[64];

  res[0]=0x89ABCDEF;
  res[1]=0x01234567;
  res[2]=0x76543210;
  res[3]=0xFEDCBA98;
  res[4]=0xC3B2E187;
  res[5]=0xF096A5B4;

  for(i=length; i>=64; i-=64)
    {
#ifdef BIG_ENDIAN
      for(j=0; j<64; j++)
	temp[j^3] = ((byte*)str)[j];
      tiger_compress(((word32*)temp), res);
#else
      tiger_compress(str, res);
#endif
      str += 16;
    }

#ifdef BIG_ENDIAN
  for(j=0; j<i; j++)
    temp[j^3] = ((byte*)str)[j];

  temp[j^3] = 0x01;
  j++;
  for(; j&7; j++)
    temp[j^3] = 0;
#else
  for(j=0; j<i; j++)
    temp[j] = ((byte*)str)[j];

  temp[j++] = 0x01;
  for(; j&7; j++)
    temp[j] = 0;
#endif
  if(j>56)
    {
      for(; j<64; j++)
	temp[j] = 0;
      tiger_compress(((word32*)temp), res);
      j=0;
    }

  for(; j<56; j++)
    temp[j] = 0;
  ((word32*)(&(temp[56])))[0] = ((word32)length)<<3;
  ((word32*)(&(temp[56])))[1] = 0;
  tiger_compress(((word32*)temp), res);
}

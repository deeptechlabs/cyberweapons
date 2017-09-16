#include "des-private.h"

/* Expand 32-bit input block according to E-permutation so that each
   output-byte contains 6 bits of output data */

int
des_expand(ibuf,obuf)

des_u_char	*ibuf,*obuf;

{
  des_u_long	L;
  des_u_char	*p;

#if BIG_ENDIAN
  copy4(ibuf[0],L);
  p = obuf+3;
  *p = L;
  L >>= 3; *--p = L;
  L >>= 4; *--p = L;
  L >>= 4; *--p = L;
  p = obuf+7;
  L >>= 4; *p = L;
  L >>= 4; *--p = L;
  L >>= 4; *--p = L;
  L >>= 4; *--p = L;
  obuf[3] <<= 1;
  *p |= obuf[3] << 4;
  L >>= 4; obuf[3] |= L;
#else
  copy4(ibuf[0],L);
  p = obuf;
  *p++ = L;
  L >>= 3; *p++ = L;
  L >>= 4; *p++ = L;
  L >>= 4; *p++ = L;
  L >>= 4; *p++ = L;
  L >>= 4; *p++ = L;
  L >>= 4; *p++ = L;
  L >>= 4; *p = L;
  obuf[0] <<= 1;
  *p |= obuf[0] << 4;
  L >>= 4; obuf[0] |= L;
#endif
  val4(obuf[0]) &= 0x3f3f3f3f;
  val4(obuf[4]) &= 0x3f3f3f3f;
}

/* Unexpand 8 6-bit bytes into one 32-bit block */

des_u_long
des_unexpand(ibuf)

des_u_char	*ibuf;

{
  des_u_long	L;
  des_u_char	*p;

#if BIG_ENDIAN
  p = ibuf+4;
  L = *p++;			/* 27 .. */
  L = (L << 4) | *p++;		/* 23 .. */
  L = (L << 4) | *p++;		/* 19 .. */
  L = (L << 4) | *p;		/* 15 .. */
  p = ibuf;
  L = (L << 4) | *p++;		/* 11 .. */
  L = (L << 4) | *p++;		/* 7 .. */
  L = (L << 4) | *p++;		/* 3 .. */
  L = (L << 3) | (*p >> 1);	/* 0 .. */
#else
  p = ibuf+8;
  L = *--p;			/* 27 .. */
  L = (L << 4) | *--p;		/* 23 .. */
  L = (L << 4) | *--p;		/* 19 .. */
  L = (L << 4) | *--p;		/* 15 .. */
  L = (L << 4) | *--p;		/* 11 .. */
  L = (L << 4) | *--p;		/* 7 .. */
  L = (L << 4) | *--p;		/* 3 .. */
  L = (L << 3) | (*--p >> 1);	/* 0 .. */
#endif
  return L;
}


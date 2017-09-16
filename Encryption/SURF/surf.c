#include "surf.h"
#include "uint32.h"

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - b)))

#define MUSH(i,b) t[i] = x = t[i] + (((x ^ dex[i]) + sum) ^ ROTATE(x,b));

void surf(out,in,dex)
uint32 out[8];
uint32 in[12];
uint32 dex[32];
{
  uint32 t[12];
  int r;
  int i;
  int loop;
  uint32 x;
  uint32 sum = 0;

  for (i = 0;i < 8;++i) out[i] = dex[24 + i];

  for (loop = 0;loop < 2;++loop) {
    for (i = 0;i < 12;++i) t[i] = in[i] ^ dex[12 + i];
    x = t[11];
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5)
      MUSH(1,7)
      MUSH(2,9)
      MUSH(3,13)
      MUSH(4,5)
      MUSH(5,7)
      MUSH(6,9)
      MUSH(7,13)
      MUSH(8,5)
      MUSH(9,7)
      MUSH(10,9)
      MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}
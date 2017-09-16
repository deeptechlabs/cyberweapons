
/*
 * redoc3.c : Source code for the REDOC III block cipher
 *
 * Part of the Python Cryptography Toolkit, version 1.0.0
 *
 * Copyright (C) 1995, A.M. Kuchling
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */
  
 
typedef unsigned char byte;

typedef struct 
{
  PCTObject_HEAD
  byte key_table[2560], mask_table[16];
} REDOC3object;

unsigned int	prime[35] 	=	{  1,   3,   5,   7,  11,  13,  17,
					  19,  23,  29,  31,  37,  41,  43,
					  47,  53,  59,  61,  67,  71,  73,
					  79,  83,  89,  97, 101, 103, 107,
					 109, 113, 127, 131, 137, 139, 149};

void	REDOC3init(self, key, keylen)
     REDOC3object *self;
     byte *key;
     int keylen;
{
  int		data_point, pi, pii;
  int seed, data_value,	mask_counter;
  byte	*mask_pointer;

  for (pi = 1; pi <= keylen; ++pi)
  {
    if (pi != keylen)
    {   seed = (key[pi-1] << 8) + key[pi];
    }
     else
    {   seed = (key[pi-1] << 8) + key[0];
    }

    data_point = 0;
    
    for (pii = 0; pii < 2560; ++pii)
    { data_point += prime[pi];
      if (data_point > 2559) data_point -= 2560;

      data_value = seed;

      self->key_table[data_point] = data_value >> 8;
      if ( (data_point + 1) != 2559)
	self->key_table[data_point + 1] = data_value & 255;
       else
	self->key_table[0] = data_value & 255;
    }
  }
  mask_pointer = self->mask_table;
  mask_counter = 0;

  for (pi = 0; pi < 16; ++pi) self->mask_table[pi] = 0;

  for (pi = 0; pi < 2560; ++pi)
  { *mask_pointer ^= self->key_table[pi];
    ++mask_pointer;
    ++mask_counter;
    if (mask_counter == 16)
      {  mask_counter = 0;
	 mask_pointer = self->mask_table;
      }
  }
}

void inline REDOC3encrypt (self, data)
     REDOC3object *self;
     byte *data;
{
  int	pi, pii, key_value, mask_point;
  byte	*mask_table = self->mask_table, *key_table=self->key_table;

  for (pi = 0; pi < 8; ++pi)
  {  key_value = (data[pi] ^ mask_table[pi])<<3;
     for (pii = 0; pii < 8; ++pii)
     { if (pi != pii) data[pii] ^= key_table[key_value + pii];
     }
  }

  mask_point=8;
  for (pi = 0; pi < 8; ++pi)
  {
     key_value = (data[pi] ^ mask_table[mask_point]) <<3;
     ++mask_point;
     for (pii = 0; pii < 8; ++pii)
     { if (pi != pii) data[pii] ^= key_table[key_value + pii];
     }
  }
}

void inline REDOC3decrypt (self, data)
     REDOC3object *self;
     byte *data;
{
  int	pi, pii, key_value, mask_point;
  byte	*mask_table=self->mask_table;
  byte  *key_table=self->key_table;
  
  mask_point = 15;
  for (pi = 7; pi >= 0; --pi)
  {  key_value = (data[pi] ^ mask_table[mask_point]) <<3;
     --mask_point;
     for (pii = 0; pii < 8; ++pii)
     { if (pi != pii) data[pii] ^= key_table[key_value + pii];
     }
  }

  for (pi = 7; pi >= 0; --pi)
  {  key_value = (data[pi] ^ mask_table[pi]) << 3;
     for (pii = 0; pii < 8; ++pii)
     { if (pi != pii) data[pii] ^= key_table[key_value + pii];
     }
  }
}

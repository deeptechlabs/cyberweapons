#include <stdio.h>
#include <string.h>

#define  byte unsigned int

byte 	permtable[256][10];
byte	esubtable[16][256];
byte	dsubtable[16][256];
byte	encltable[256][3][5];
byte	key_x[10] = {114, 77, 62, 14, 91, 113, 233, 170, 56, 152};
byte    key_y[10] = {255, 222, 26, 155, 213, 248, 12, 109, 78, 95};
byte	keystable[256][10];
byte	masktable[10][10];
byte	dataval[10] = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74};


int randy (lo, hi, stval)
  int		lo, hi;
  byte		*stval;
{
  int   	fcnt, fscnt, fnum;
  short int 	fg;
  byte		*cuval, *tsval;

  fnum = hi - lo + 1;
  cuval = stval;

  fcnt = 0;
  while (fcnt < fnum)
  {  *cuval = rand() % fnum;
     while (*cuval >= fnum) *cuval -= fnum;
     *cuval += lo;

     if (fcnt > 0)
     {  fg = 1;
	tsval = stval;
	for (fscnt = 0; fscnt < fcnt; ++fscnt)
	{  if (*tsval == *cuval) fg = 0;
	   ++tsval;
	}
	if (fg == 1)
	{  ++fcnt;
	   ++cuval;
	}
     }
     if (fcnt == 0)
     { ++fcnt;
       ++cuval;
     }
  }
  return (fnum);
}

int create_permutations (num, stval, pen, cdimp)
  int	num;
  byte	*stval;
  int	pen;
  byte	*cdimp;
{
  int 	fi, fcnt, ccnt;
  byte	*cdvalue;

  fcnt = pen - 1;
  --num;
  ccnt = 0;
  cdvalue = cdimp;

  srand (*cdvalue);
  for (fi = 0; fi <= num; ++fi)
  {  stval += randy (0,fcnt,stval);
     ++ccnt;
     if (ccnt == 6)
     {  ccnt = 0;
	++cdvalue;
	srand (*cdvalue);
     }
  }
  return (0);
}

int create_substitutions (num, stval, sun, cdimp)
  int	num;
  byte	*stval;
  int	sun;
  byte	*cdimp;
{
  int	fi, fcnt;
  byte	*cdvalue;

  fcnt = sun - 1;
  --num;
  cdvalue = cdimp;
  srand (*cdvalue);
  for (fi = 0; fi <= num; ++fi)
  {  stval += randy (0, fcnt, stval);
     ++cdvalue;
     srand (*cdvalue);
  }

  return (0);
}

int create_inverse_table (stval1, stval2, sun)
  byte	*stval1, *stval2;
  int	sun;
{
  int	fi, fcnt;
  byte	*temp_value;

  fcnt = sun - 1;
  for (fi = 0; fi <= fcnt; ++fi)
  { temp_value = stval2 + *stval1;
    *temp_value = fi;
    ++stval1;
  }

  return (sun);
}

int create_inverse_substitutions (num, val1, val2, sun)
  int 	num;
  byte	*val1, *val2;
  int	sun;
{
  int	fi, fcnt;

  --num;
  for (fi = 0; fi <= num; ++fi)
  { create_inverse_table (val1, val2, sun);
    val1 += sun;
    val2 += sun;
  }

  return (0);
}

int create_enclave_table (stval)
  byte *stval;
{
  int		fi, fii;
  byte		*cuval, *temp1, *temp2;
  short int	fg;

  fg = 1;
  while (fg == 1)
  { cuval = stval;
    for (fi = 0; fi <= 2; ++fi)
      cuval += randy (0, 4, cuval);
    fg = 0;
    cuval = stval;
    for (fi = 0; fi <= 4; ++fi)
    {  temp1 = cuval + 5;
       temp2 = cuval + 10;
       if ((*cuval == *temp1) || (*cuval == *temp2) || (*temp1 == *temp2))
	 fg = 1;
       ++cuval;
    }
  }
  return (15);
}

int create_enclaves (num, val1, cdimp)
  int	num;
  byte 	*val1;
  byte	*cdimp;
{
  int	fi, ccnt;
  byte 	*cdvalue;

  --num;
  ccnt = 0;
  cdvalue = cdimp;
  srand (*cdvalue);
  for (fi = 0; fi <= num; ++ fi)
  { create_enclave_table (val1);
    val1 += 15;
    ++ccnt;
    if (ccnt == 6)
    {  ccnt = 0;
       ++cdvalue;
       srand (*cdvalue);
    }
  }

  return (0);
}

int check_enclave_columns (clmn1, clmn2)
  byte	*clmn1, *clmn2;
{
  int	fi, fg;

  fg = 1;
  for (fi = 0; fi <= 4; ++fi)
  {  if (*clmn1 != *clmn2) fg = 0;
     ++clmn1;
     ++clmn2;
  }

  return (fg);
}

int save_function_tables (peb, sub, isb, enb, pen, sun, fl)
  byte 	*peb, *sub, *isb, *enb;
  int	pen, sun;
  FILE	*fl;
{
  int	fi, fii, fiii, fcnt;

  fcnt = 256 * pen;
  while (fcnt > 0)
  { fputc (*peb, fl);
    ++peb;
    --fcnt;
  }

  fcnt = 16 * sun;
  while (fcnt > 0)
  { fputc (*sub, fl);
    ++sub;
    --fcnt;
  }

  fcnt = 16 * sun;
  while (fcnt > 0)
  {  fputc (*isb, fl);
     ++isb;
     --fcnt;
  }

  fcnt = 256 * 15;
  while (fcnt > 0)
  { fputc (*enb, fl);
    ++enb;
    --fcnt;
  }

  return (0);
}

int permutate (permval, dataval)
  byte *permval, *dataval;
{
  byte 	*temp1, *temp2;
  byte	work_space[20];
  int	fi;

  temp1 = dataval;
  for (fi = 0; fi <= 9; ++fi)
  { temp2 = *permval + &work_space[0];
    *temp2 = *dataval;
    ++dataval;
    ++permval;
  }

  dataval = temp1;
  temp2 = &work_space[0];
  for (fi = 0; fi <= 9; ++fi)
  {  *dataval = *temp2;
     ++temp2;
     ++dataval;
  }

  return (0);
}

int inverse_permutate (permval, dataval)
  byte	*permval, *dataval;
{
  byte	*temp1, *temp2;
  int	fi;
  byte	work_space[20];

  temp1 = dataval;
  for (fi = 0; fi <= 9; ++fi)
  {  temp2 = temp1 + *permval;
     work_space[fi] = *temp2;
     ++permval;
  }
  dataval = temp1;
  temp2 = &work_space[0];
  for (fi = 0; fi <= 9; ++fi)
  { *dataval = *temp2;
    ++temp2;
    ++dataval;
  }

  return (0);
}


int substitute (skip, subval, dataval)
  int	skip;
  byte	*subval, *dataval;
{
  int	fi;
  byte	*temp;

  for (fi = 0; fi <= 9; ++fi)
  { if (fi != skip)
    { temp = subval + *dataval;
      *dataval = *temp;
    }
    ++dataval;
  }

  return (skip);
}


int add_clave (encval, dataval)
  byte *encval, *dataval;
{
  int	fi, fii;
  byte	*temp1, *temp2, *temp3;

  for (fi = 0; fi <= 4; ++fi)
  { temp2 = encval + 5;
    temp3 = encval + 10;
    temp1 = dataval + *encval;
    temp2 = dataval + *temp2;
    temp3 = dataval + *temp3;
    *temp1 = (*temp1 + *temp2 + *temp3) % 256;
    while (*temp1 > 255) *temp1 -= 256;
    ++encval;
  }

  return (0);
}

int subtract_clave (encval, dataval)
  byte	*encval, *dataval;
{
  int	fi, fii;
  byte	*temp1, *temp2, *temp3;
  encval += 4;
  for (fi = 0; fi <= 4; ++fi)
  {  temp2 = encval + 5;
     temp3 = encval + 10;
     temp1 = dataval + *encval;
     temp2 = dataval + *temp2;
     temp3 = dataval + *temp3;
     *temp1 = (*temp1 - *temp2 - *temp3) + 512;
     while (*temp1 > 255) *temp1 += 256;
     --encval;
  }

  return (0);
}


int right_add_merge (dataval)
  byte *dataval;
{
  int 	fi;
  byte	*left, *right;

  left = dataval;
  right = dataval + 5;

  for (fi = 0; fi <=4; ++fi)
  { *right = *right ^ *left;
    while (*right > 255) *right -= 256;
    ++right;
    ++left;
  }

  return (0);
}

int right_sub_merge (dataval)
  byte *dataval;
{
  int	fi;
  byte	*left, *right;

  left = dataval;
  right = dataval + 5;

  for (fi = 0; fi <= 4; ++fi)
  {  *right = *right ^ *left;
     while (*right < 0) *right += 256;
     ++right;
     ++left;
  }

  return (0);
}


int left_add_merge (dataval)
  byte 	*dataval;
{
  int	fi;
  byte	*left, *right;

  left = dataval;
  right = dataval + 5;

  for (fi = 0; fi <= 4; ++fi)
  { *left = *right ^ *left;
    while (*left > 255) *left -= 256;
    ++right;
    ++left;
  }

  return (0);
}

int left_sub_merge (dataval)
  byte	*dataval;
{
  int	fi;
  byte	*left, *right;

  left = dataval;
  right = dataval + 5;

  for (fi = 0; fi <= 4; ++fi)
  {  *left = *left ^ *right;
     while (*left < 0) *left += 256;
     ++right;
     ++left;
  }

  return (0);
}

int right_enclave (fenc, senc, dval)
  byte *fenc, *senc, *dval;
{
  byte	*pval;

  pval = dval + 5;
  add_clave (fenc, pval);
  add_clave (senc, pval);
  right_add_merge (dval);

  return (0);
}

int inverse_right_enclave (fenc, senc, dval)
  byte *fenc, *senc, *dval;
{
  byte 	*pval;

  pval = dval + 5;
  right_sub_merge (dval);
  subtract_clave (senc, pval);
  subtract_clave (fenc, pval);
  return (0);
}


int left_enclave (fenc, senc, dval)
  byte *fenc, *senc, *dval;
{
  add_clave (fenc, dval);
  add_clave (senc, dval);
  left_add_merge (dval);
  return (0);
}


int inverse_left_enclave (fenc, senc, dval)
  byte *fenc, *senc, *dval;
{
  left_sub_merge (dval);
  subtract_clave (senc, dval);
  subtract_clave (fenc, dval);
  return (0);
}


int key_xor (skip, kval, dval)
  int	skip;
  byte	*kval, *dval;
{
  int	fi;

  for (fi = 0; fi <= 9; ++fi)
  {  if (fi != skip) *dval ^= *kval;
     ++kval;
     ++dval;
  }

  return (0);
}

int key_add (skip, kval, dval)
  int	skip;
  byte	*kval, *dval;
{
  int	fi;

  for (fi = 0; fi <= 9; ++fi)
  {  if (fi != skip) *dval += *kval;
     while (*dval > 255) *dval -= 256;
     ++kval;
     ++dval;
  }

  return (0);
}


int key_sub (skip, kval, dval)
  int	skip;
  byte	*kval, *dval;
{
  int	fi;

  for (fi = 0; fi <= 9; ++fi)
  {  if (fi != skip) *dval -= *kval;
     while (*dval < 0) *dval += 256;
     ++kval;
     ++dval;
  }

  return (0);
}


int create_key_table (kx, kyval, tableval, peb, sub, enb, pen, sun, enn)
  byte	*kx, *kyval, *tableval, *peb, *sub, *enb;
  int	pen, sun, enn;
{
  int	fi, fii;
  unsigned long int	a, b, c, d, m, n, z;
  byte			*tempval, *fp1, *fp2, *adval, *ev1, *ev2, *ev3, *ev4;
  byte			*kxval, keyxxx[10];

  tempval = tableval;

  kxval = &keyxxx[0];
  for (fii = 0; fii <= 9; ++fii)
  { *tableval = *kyval;
    keyxxx[fii] = *kx;
    ++kx;
    ++kyval;
    ++tableval;
  }

  for (fi = 0; fi <= 255; ++fi)
  {  tableval = tempval;

     a = *kxval ^ *tableval;
     while (a > 255) a -= 256;
     ++kxval;
     ++tableval;

     b = *kxval ^ *tableval;
     while (b > 255) b -= 256;
     ++kxval;
     ++tableval;

     c = *kxval ^ *tableval;
     while (c > 255) c -= 256;
     ++kxval;
     ++tableval;

     d = *kxval ^ *tableval;
     while (d > 255) d -= 256;
     ++kxval;
     ++tableval;

     m = *kxval ^ *tableval ^ *(kxval+1) ^ *(tableval+1);
     while (m > 255) m -= 256;
     kxval += 2;
     tableval += 2;

     n = *kxval ^ *tableval ^ *(kxval+1) ^ *(tableval+1);
     while (n > 255) n -= 256;
     kxval += 2;
     tableval += 2;

     z = *kxval ^ *tableval ^ *(kxval+1) + *(tableval+1);
     while (z > 255) z -= 256;
     kxval += 2;
     tableval += 2;

     n *= pen;
     adval = peb + n;
     permutate (adval, tempval);

     while (m > 15) m -= 16;
     m *= sun;
     adval = sub + m;
     substitute (10, adval, tempval);

     a *= enn;
     ev1 = enb + a;
     b *= enn;
     ev2 = enb + b;
     c *= enn;
     ev3 = enb + c;
     d *= enn;
     ev4 = enb + d;

     left_enclave (ev1, ev2, tempval);
     right_enclave (ev3, ev4, tempval);

     z *= pen;
     adval = peb + z;
     kxval -= 10;
     permutate (adval, kxval);

     if (fi < 255)
     {  tableval = tempval;
	tempval += 10;

	for (fii = 0; fii <= 9; ++fii)
	{  *tempval = *tableval;
	   ++tableval;
	   ++tempval;
	}

	tempval -= 10;
     }
  }
  return (0);
}

int create_mask_table (ktval, mtval)
  byte 	*ktval, *mtval;
{
  int   fi, fii;
  byte	*temp, *ktemp;

  temp = mtval;
  for (fi = 0; fi <= 99; ++fi)
  {  *mtval = 0;
     ++mtval;
  }

  mtval = temp;

  for (fi = 0; fi <= 25; ++fi)
  {  for (fii = 0; fii <= 99; ++fii)
     {  *mtval ^= *ktval;
	while (*mtval > 255) *mtval -= 256;
	++mtval;
	++ktval;
     }
     mtval = temp;
  }

  return (0);
}

int d_redoc_ii (keyval, maskval, dataval, peb, isb, enb,
		pen, isn, enn)
  byte	*keyval, *maskval, *dataval, *peb, *isb, *enb;
  int	pen, isn, enn;
{
  int	a, b, c, d, w, z, fi, pi;
  int   round, table, skip1, skip2;
  byte	*datapoint, *maskpoint, *temp;
  byte	*taddress, *a_address, *b_address, *c_address, *d_address;

  maskpoint = maskval + 89;
  datapoint = dataval + 9;

  round = 9;

  skip1 = 9;
  skip2 = 0;

  table = 0;
  temp = dataval;


  for (fi = 0; fi <= 9; ++fi)
  { table ^= *temp;
    ++temp;
  }

  table ^= *maskpoint;


  while (table > 255) table -= 256;
  table *= pen;
  taddress = peb + table;

  inverse_permutate (taddress, dataval);

  datapoint = dataval;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  table *= 10;
  taddress = keyval + table;

  key_xor (skip2, taddress, dataval);

  w = round - 1;
  while (w < 0) w += 5;
  while (w > 4) w -= 5;
  z = w + 1;
  while (z > 4) z -= 5;

  maskpoint -= 10;
  temp = dataval + z;
  d = *temp ^ *maskpoint;
  while (d > 255) d -= 256;
  d *= enn;
  d_address = enb + d;

  maskpoint -= 10;
  temp = dataval + w;
  c = *temp ^ *maskpoint;
  while (c > 255) c -= 256;
  c *= enn;
  c_address = enb + c;


  inverse_right_enclave (c_address, d_address, dataval);

  maskpoint -= 10;

  temp = dataval + 5 + z;
  b = *temp ^ *maskpoint;
  while (b > 255) b -= 256;
  b *= enn;
  b_address = enb + b;

  maskpoint -= 10;
  temp = dataval + 5 + w;
  a = *temp ^ *maskpoint;
  while (a > 255) a -= 256;
  a *= enn;
  a_address = enb + a;

  inverse_left_enclave (a_address, b_address, dataval);

  datapoint = dataval + 9;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  table *= 10;
  taddress = keyval + table;

  key_xor (skip1, taddress, dataval);

  datapoint = dataval;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  while (table > 15) table -= 16;
  table *= isn;
  taddress = isb + table;
  substitute (skip2, taddress, dataval);

  datapoint = dataval + 9;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  while (table > 15) table -= 16;
  table *= isn;
  taddress = isb + table;
  substitute (skip1, taddress, dataval);

  --datapoint;
  maskpoint += 79;

  for (round = 8; round >= 0; --round)
  {  skip1 = round;
     skip2 = round + 1;

    table = 0;
    temp = dataval;

    for (fi = 0; fi <= 9; ++fi)
    { table ^= *temp;
      ++temp;
    }
    table ^= *maskpoint;
    while (table > 255) table -= 256;
    table *= pen;
    taddress = peb + table;
    inverse_permutate (taddress, dataval);

    datapoint = dataval + skip2;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    table *= 10;
    taddress = keyval + table;
    key_xor (skip2, taddress, dataval);

    w = round - 1;
    while (w < 0) w += 5;
    while (w > 4) w -= 5;
    z = w + 1;
    while (z > 4) z -= 5;

    maskpoint -= 10;
    temp = dataval + z;
    d = *temp ^ *maskpoint;
    while (d > 255) d -= 256;
    d *= enn;
    d_address = enb + d;

    maskpoint -= 10;
    temp = dataval + w;
    c = *temp ^ *maskpoint;
    while (c > 255) c -= 256;
    c *= enn;
    c_address = enb + c;

    inverse_right_enclave (c_address, d_address, dataval);

    maskpoint -= 10;
    temp = dataval + 5 + z;
    b = *temp ^ *maskpoint;
    while (b > 255) b -= 256;
    b *= enn;
    b_address = enb + b;

    maskpoint -= 10;
    temp = dataval + 5 + w;
    a = *temp ^ *maskpoint;
    while (a > 255) a -= 256;
    a *= enn;
    a_address = enb + a;

    inverse_left_enclave (a_address, b_address, dataval);

    datapoint = dataval + skip1;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    table *= 10;
    taddress = keyval + table;
    key_xor (skip1, taddress, dataval);

    datapoint = dataval + skip2;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= isn;
    taddress = isb + table;
    substitute (skip2, taddress, dataval);

    datapoint = dataval + skip1;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= isn;
    taddress = isb + table;
    substitute (skip1, taddress, dataval);

    --datapoint;
    maskpoint += 79;
  }

  return (0);

}



int e_redoc_ii (keyval, maskval, dataval, peb, sub, enb,
		pen, sun, enn, ken)
  byte	*keyval, *maskval, *dataval, *peb, *sub, *enb;
  int	pen, sun, enn, ken;
{
  int	a, b, c, d, w, z, fi, pi;
  int	round, table, skip1, skip2;
  byte	*datapoint, *maskpoint, *temp, *taddress;
  byte	*a_address, *b_address, *c_address, *d_address;


  maskpoint = maskval;
  datapoint = dataval;

  for (round = 0; round <= 8; ++round)
  { skip1 = round;
    skip2 = round + 1;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= sun;
    taddress = table + sub;

    substitute (skip1, taddress, dataval);

    ++datapoint;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= sun;
    taddress = sub + table;

    substitute (skip2, taddress, dataval);

    --datapoint;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    table *= ken;
    taddress = keyval + table;

    key_xor (skip1, taddress, dataval);

    w = round - 1;
    while (w < 0) w += 5;
    while (w > 4) w -= 5;
    z = w + 1;
    while (z > 4) z -= 5;

    maskpoint += 10;
    temp = dataval + 5 + w;
    a = *temp ^ *maskpoint;
    while (a > 255) a -= 256;
    a *= enn;
    a_address = enb + a;

    maskpoint += 10;
    temp = dataval + 5 + z;
    b = *temp ^ *maskpoint;
    while (b > 255) b -= 256;
    b *= enn;
    b_address = enb + b;

    left_enclave (a_address, b_address, dataval);

    maskpoint += 10;
    temp = dataval + w;
    c = *temp ^ *maskpoint;
    while (c > 255) c -= 256;
    c *= enn;
    c_address = enb + c;

    maskpoint += 10;
    temp = dataval + z;
    d = *temp ^ *maskpoint;
    while (d > 255) d -= 256;
    d *= enn;
    d_address = enb + d;

    right_enclave (c_address, d_address, dataval);

    ++datapoint;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    table *= 10;
    taddress = keyval + table;

    key_xor (skip2, taddress, dataval);

    maskpoint += 10;
    table = 0;
    temp = dataval;

    for (fi = 0; fi <= 9; ++fi)
    {  table ^= *temp;
       ++temp;
    }
    /* while (table > 255) table -= 256; */
    table ^= *maskpoint;
    table *= pen;
    taddress = peb + table;

    permutate (taddress, dataval);
    maskpoint -= 79;

  }

  round = 9;

  skip1 = 9;
  skip2 = 0;


    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= sun;
    taddress = table + sub;

    substitute (skip1, taddress, dataval);

    datapoint = dataval;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= sun;
    taddress = sub + table;

    substitute (skip2, taddress, dataval);

    datapoint = dataval + 9;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    table *= ken;
    taddress = keyval + table;

    key_xor (skip1, taddress, dataval);

    w = round - 1;
    while (w < 0) w += 5;
    while (w > 4) w -= 5;
    z = w + 1;
    while (z > 4) z -= 5;

    maskpoint += 10;
    temp = dataval + 5 + w;
    a = *temp ^ *maskpoint;
    while (a > 255) a -= 256;
    a *= enn;
    a_address = enb + a;

    maskpoint += 10;
    temp = dataval + 5 + z;
    b = *temp ^ *maskpoint;
    while (b > 255) b -= 256;
    b *= enn;
    b_address = enb + b;

    left_enclave (a_address, b_address, dataval);


    maskpoint += 10;
    temp = dataval + w;
    c = *temp ^ *maskpoint;
    while (c > 255) c -= 256;
    c *= enn;
    c_address = enb + c;

    maskpoint += 10;
    temp = dataval + z;
    d = *temp ^ *maskpoint;
    while (d > 255) d -= 256;
    d *= enn;
    d_address = enb + d;

    right_enclave (c_address, d_address, dataval);

    datapoint = dataval;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    table *= 10;
    taddress = keyval + table;

    key_xor (skip2, taddress, dataval);

    maskpoint += 10;
    table = 0;
    temp = dataval;

    for (fi = 0; fi <= 9; ++fi)
    {  table ^= *temp;
       ++temp;
    }
    while (table > 255) table -= 256;
    table ^= *maskpoint;
    table *= pen;
    taddress = peb + table;

    permutate (taddress, dataval);

  return (0);
}


int pe_redoc_ii (keyval, maskval, dataval, peb, sub, enb,
		pen, sun, enn, ken)
  byte	*keyval, *maskval, *dataval, *peb, *sub, *enb;
  int	pen, sun, enn, ken;
{
  int	a, b, c, d, w, z, fi, pi;
  int	round, table, skip1, skip2;
  byte	*datapoint, *maskpoint, *temp, *taddress;
  byte	*a_address, *b_address, *c_address, *d_address;


  FILE	*fl;

  fl = fopen ("ENCRYPT.TXT","wt");


  maskpoint = maskval;
  datapoint = dataval;

  for (round = 0; round <= 8; ++round)
  { skip1 = round;
    skip2 = round + 1;

    fprintf (fl,"round = %2d          skip1 = %2d     skip2 = %2d \n\r\n\r", round, skip1, skip2);

    table = *datapoint ^ *maskpoint;
    fprintf (fl, "esubtable = (DATA xor MASK) mod 16 = (%3d xor %3d) mod 16 \n\r = %3d mod 16 = ", *datapoint, *maskpoint, table);
    while (table > 15) table -= 16;
    fprintf (fl, "%3d \n\r\n\r", table);
    table *= sun;
    taddress = table + sub;

    fprintf (fl,"DATA BEFORE SUBSTITUTION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    substitute (skip1, taddress, dataval);
    fprintf (fl,"DATA AFTER  SUBSTITUTION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    ++datapoint;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    fprintf (fl, "esubtable = (DATA xor MASK) mod 16 = (%3d xor %3d) mod 16 \n\r = %3d mod 16 = ", *datapoint, *maskpoint, table);
    while (table > 15) table -= 16;
    fprintf (fl, "%3d \n\r\n\r", table);
    table *= sun;
    taddress = sub + table;

    fprintf (fl,"DATA BEFORE SUBSTITUTION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    substitute (skip2, taddress, dataval);
    fprintf (fl,"DATA AFTER  SUBSTITUTION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    --datapoint;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    fprintf (fl, " keytable = DATA xor MASK = %3d xor %3d = %3d \n\r\n\r", *datapoint, *maskpoint, table);
    table *= ken;
    taddress = keyval + table;

    fprintf (fl,"DATA BEFORE KEY ADDITION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    key_xor (skip1, taddress, dataval);
    fprintf (fl,"DATA AFTER  KEY ADDITION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    w = round - 1;
    while (w < 0) w += 5;
    while (w > 4) w -= 5;
    z = w + 1;
    while (z > 4) z -= 5;

    maskpoint += 10;
    temp = dataval + 5 + w;
    a = *temp ^ *maskpoint;
    fprintf (fl,"w = %3d   :  a = DATA xor MASK = %3d xor %3d = %3d \n\r",w , *temp, *maskpoint, a);
    while (a > 255) a -= 256;
    a *= enn;
    a_address = enb + a;

    maskpoint += 10;
    temp = dataval + 5 + z;
    b = *temp ^ *maskpoint;
    fprintf (fl,"z = %3d   :  b = DATA xor MASK = %3d xor %3d = %3d \n\r", z, *temp, *maskpoint, b);
    while (b > 255) b -= 256;
    b *= enn;
    b_address = enb + b;

    fprintf (fl,"DATA BEFORE LEFT ENCLAVE  : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    left_enclave (a_address, b_address, dataval);
    fprintf (fl,"DATA AFTER  LEFT ENCLAVE  : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");


    maskpoint += 10;
    temp = dataval + w;
    c = *temp ^ *maskpoint;
    fprintf (fl,"w = %3d   :  c = DATA xor MASK = %3d xor %3d = %3d \n\r",w , *temp, *maskpoint, c);
    while (c > 255) c -= 256;
    c *= enn;
    c_address = enb + c;

    maskpoint += 10;
    temp = dataval + z;
    d = *temp ^ *maskpoint;
    fprintf (fl,"z = %3d   :  d = DATA xor MASK = %3d xor %3d = %3d \n\r", z, *temp, *maskpoint, d);
    while (d > 255) d -= 256;
    d *= enn;
    d_address = enb + d;

    fprintf (fl,"DATA BEFORE RIGHT ENCLAVE : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    right_enclave (c_address, d_address, dataval);
    fprintf (fl,"DATA AFTER  RIGHT ENCLAVE : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    ++datapoint;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    fprintf (fl, " keytable = DATA xor MASK = %3d xor %3d = %3d \n\r\n\r", *datapoint, *maskpoint, table);
    table *= 10;
    taddress = keyval + table;

    fprintf (fl,"DATA BEFORE KEY ADDITION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    key_xor (skip2, taddress, dataval);
    fprintf (fl,"DATA AFTER  KEY ADDITION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    maskpoint += 10;
    table = 0;
    temp = dataval;

    fprintf (fl,"permtable = ");
    for (fi = 0; fi <= 9; ++fi)
    {  table ^= *temp;
       if (fi < 9) fprintf (fl,"%3d ^", *temp);
	 else fprintf (fl,"%3d = ",*temp);
       ++temp;
    }
    /* while (table > 255) table -= 256; */
    fprintf (fl,"%3d\n\r = %3d xor %3d = ", table, table, *maskpoint);
    table ^= *maskpoint;
    fprintf (fl,"%3d\n\r\n\r",table);
    table *= pen;
    taddress = peb + table;

    fprintf (fl,"DATA BEFORE PERMUTATION   : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    permutate (taddress, dataval);
    fprintf (fl,"DATA AFTER  PERMUTATION   : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");
    fprintf (fl,"\f");
    maskpoint -= 79;

  }

  round = 9;

  skip1 = 9;
  skip2 = 0;

    fprintf (fl,"round = %2d          skip1 = %2d     skip2 = %2d \n\r\n\r", round, skip1, skip2);

    table = *datapoint ^ *maskpoint;
    fprintf (fl, "esubtable = (DATA xor MASK) mod 16 = (%3d xor %3d) mod 16 /n/r = %3d mod 16 = ", *datapoint, *maskpoint, table);
    while (table > 15) table -= 16;
    fprintf (fl, "%3d \n\r\n\r");
    table *= sun;
    taddress = table + sub;

    fprintf (fl,"DATA BEFORE SUBSTITUTION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    substitute (skip1, taddress, dataval);
    fprintf (fl,"DATA AFTER  SUBSTITUTION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    datapoint = dataval;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    fprintf (fl, "esubtable = (DATA xor MASK) mod 16 = (%3d xor %3d) mod 16 /n/r = %3d mod 16 = ", *datapoint, *maskpoint, table);
    while (table > 15) table -= 16;
    fprintf (fl, "%3d \n\r\n\r");
    table *= sun;
    taddress = sub + table;

    fprintf (fl,"DATA BEFORE SUBSTITUTION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    substitute (skip2, taddress, dataval);
    fprintf (fl,"DATA AFTER  SUBSTITUTION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    datapoint = dataval + 9;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    fprintf (fl, " keytable = DATA xor MASK = %3d xor %3d = %3d", *datapoint, *maskpoint, table);
    table *= ken;
    taddress = keyval + table;

    fprintf (fl,"DATA BEFORE KEY ADDITION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    key_xor (skip1, taddress, dataval);
    fprintf (fl,"DATA AFTER  KEY ADDITION 1: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    w = round - 1;
    while (w < 0) w += 5;
    while (w > 4) w -= 5;
    z = w + 1;
    while (z > 4) z -= 5;

    maskpoint += 10;
    temp = dataval + 5 + w;
    a = *temp ^ *maskpoint;
    fprintf (fl,"w = %3d   :  a = DATA xor MASK = %3d xor %3d = %3d \n\r",w , *temp, *maskpoint, a);
    while (a > 255) a -= 256;
    a *= enn;
    a_address = enb + a;

    maskpoint += 10;
    temp = dataval + 5 + z;
    b = *temp ^ *maskpoint;
    fprintf (fl,"z = %3d   :  b = DATA xor MASK = %3d xor %3d = %3d \n\r", z, *temp, *maskpoint, b);
    while (b > 255) b -= 256;
    b *= enn;
    b_address = enb + b;

    fprintf (fl,"DATA BEFORE LEFT ENCLAVE  : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    left_enclave (a_address, b_address, dataval);
    fprintf (fl,"DATA AFTER  LEFT ENCLAVE  : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");


    maskpoint += 10;
    temp = dataval + w;
    c = *temp ^ *maskpoint;
    fprintf (fl,"w = %3d   :  c = DATA xor MASK = %3d xor %3d = %3d \n\r",w , *temp, *maskpoint, c);
    while (c > 255) c -= 256;
    c *= enn;
    c_address = enb + c;

    maskpoint += 10;
    temp = dataval + z;
    d = *temp ^ *maskpoint;
    fprintf (fl,"z = %3d   :  d = DATA xor MASK = %3d xor %3d = %3d \n\r", z, *temp, *maskpoint, d);
    while (d > 255) d -= 256;
    d *= enn;
    d_address = enb + d;

    fprintf (fl,"DATA BEFORE RIGHT ENCLAVE : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    right_enclave (c_address, d_address, dataval);
    fprintf (fl,"DATA AFTER  RIGHT ENCLAVE : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    datapoint = dataval;
    maskpoint += 10;

    table = *datapoint ^ *maskpoint;
    fprintf (fl, " keytable = DATA xor MASK = %3d xor %3d = %3d", *datapoint, *maskpoint, table);
    table *= 10;
    taddress = keyval + table;

    fprintf (fl,"DATA BEFORE KEY ADDITION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    key_xor (skip2, taddress, dataval);
    fprintf (fl,"DATA AFTER  KEY ADDITION 2: ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");

    maskpoint += 10;
    table = 0;
    temp = dataval;

    fprintf (fl,"permtable = ((");
    for (fi = 0; fi <= 9; ++fi)
    {  table ^= *temp;
       if (fi < 9) fprintf (fl,"%3d +", *temp);
	 else fprintf (fl,"%3d) mod 256) xor ",*temp);
       ++temp;
    }
    while (table > 255) table -= 256;
    table ^= *maskpoint;
    fprintf (fl,"%3d = %3d \n\r", *maskpoint, table);
    table *= pen;
    taddress = peb + table;

    fprintf (fl,"DATA BEFORE PERMUTATION   : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r");
    permutate (taddress, dataval);
    fprintf (fl,"DATA AFTER  PERMUTATION   : ");
    for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
    fprintf (fl,"\n\r\n\r");
    fprintf (fl,"\f");

    fclose (fl);

  return (0);
}

int print_permutations ()
{
  int	pcnt1, pcnt2;

  for (pcnt1 = 0; pcnt1 <= 255; ++pcnt1)
  { fprintf (stdprn, "PERMUTATION TABLE %3d = ", pcnt1);
    for (pcnt2 = 0; pcnt2 <= 9; ++pcnt2) fprintf (stdprn,"%3d",permtable[pcnt1][pcnt2]);
    fprintf (stdprn, "\n\r");
  }
  fprintf (stdprn, "\f");

  return (0);
}

int print_substitutions ()
{
  int	pcnt1, pcnt2;

  for (pcnt1 = 0; pcnt1 <= 15; ++pcnt1)
  { fprintf (stdprn,"SUBSTITUTION TABLE %2d \n\r\n\r",pcnt1);
    for (pcnt2 = 0; pcnt2 <= 255; ++pcnt2) fprintf (stdprn," %3d=>%3d ",pcnt2,esubtable[pcnt1][pcnt2]);
    fprintf (stdprn,"\f");
  }

  return (0);
}

int print_inverse_substitutions ()
{
  int	pcnt1, pcnt2;

  for (pcnt1 = 0; pcnt1 <= 15; ++pcnt1)
  { fprintf (stdprn,"INVERSE SUBSTITUTION TABLE %2d \n\r\n\r",pcnt1);
    for (pcnt2 = 0; pcnt2 <= 255; ++pcnt2) fprintf (stdprn," %3d=>%3d ",pcnt2,dsubtable[pcnt1][pcnt2]);
    fprintf (stdprn,"\f");
  }

  return (0);
}


int print_enclaves ()
{
  int p1, p2, p3, l1;

  for (p1 = 0; p1 <= 255; p1+=4)
  {  for (l1 = 0; l1 <= 3; ++l1) fprintf (stdprn, " Enclave Table %3d  ", p1+l1);
     fprintf (stdprn,"\n\r\n\r");
     for (p2 = 0; p2 <= 4; ++p2)
     {  for (l1 = 0; l1 <= 3; ++l1)
	{  fprintf (stdprn,"  ");
	   for (p3 = 0; p3 <= 2; ++p3) fprintf (stdprn, "%4d",encltable[p1+l1][p3][p2]);
	   fprintf (stdprn,"      ");
	}
	fprintf (stdprn, "\n\r");
     }
     fprintf (stdprn,"\n\r\n\r\n\r\n\r");
  }
  fprintf (stdprn, "\f");

  return (0);
}

int print_key_table ()
{
  int	fi, fii;

  for (fi = 0; fi <=255; ++fi)
  {  fprintf (stdprn, "KEY NUMBER %3d = ", fi);
     for (fii = 0; fii <= 9; ++fii) fprintf (stdprn, "%5d", keystable[fi][fii]);
     fprintf (stdprn, "\n\r");
  }
  fprintf (stdprn, "\f");

  return (0);
}

int print_mask_table ()
{
  int	fi, fii;

  for (fi = 0; fi <= 9; ++fi)
  {  fprintf (stdprn, "MASK NUMBER %3d = ", fi);
     for (fii = 0; fii <= 9; ++fii) fprintf (stdprn, "%5d", masktable[fi][fii]);
     fprintf (stdprn, "\n\r");
  }
  fprintf (stdprn, "\f");

  return (0);
}


int pd_redoc_ii (keyval, maskval, dataval, peb, isb, enb,
		pen, isn, enn)
  byte	*keyval, *maskval, *dataval, *peb, *isb, *enb;
  int	pen, isn, enn;
{
  int	a, b, c, d, w, z, fi, pi;
  int   round, table, skip1, skip2;
  byte	*datapoint, *maskpoint, *temp;
  byte	*taddress, *a_address, *b_address, *c_address, *d_address;

  FILE	*fl;

  fl = fopen ("DECRYPT.TXT","wt");

  maskpoint = maskval + 89;
  datapoint = dataval + 9;

  round = 9;

  skip1 = 9;
  skip2 = 0;

  fprintf (fl, "round = %d        skip1 = %d        skip2 = %d \n\r\n\r", round, skip1, skip2);

  table = 0;
  temp = dataval;

  fprintf (fl,"permtable = ");

  for (fi = 0; fi <= 9; ++fi)
  { table ^= *temp;
    if (fi < 9) fprintf (fl,"%3d ^ ",*temp);
      else fprintf (fl,"%3d = %3d\n\r",*temp,table);
    ++temp;
  }
  fprintf (fl,"%3d xor %3d = ",table, *maskpoint);

  table ^= *maskpoint;

  fprintf (fl,"%3d\n\r\n\r",table);

  while (table > 255) table -= 256;
  table *= pen;
  taddress = peb + table;

  fprintf (fl, "DATA BEFORE PERMUTATION : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r");
  inverse_permutate (taddress, dataval);
  fprintf (fl, "DATA  AFTER PERMUTATION : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r\n\r");

  datapoint = dataval;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  fprintf (fl," keytable = DATA xor MASK = %3d xor %3d = %3d", *datapoint, *maskpoint, table);
  table *= 10;
  taddress = keyval + table;

  fprintf (fl, "DATA BEFORE KEY XOR     : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r");
  key_xor (skip2, taddress, dataval);
  fprintf (fl, "DATA  AFTER KEY XOR     : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r\n\r");

  w = round - 1;
  while (w < 0) w += 5;
  while (w > 4) w -= 5;
  z = w + 1;
  while (z > 4) z -= 5;

  maskpoint -= 10;
  temp = dataval + z;
  d = *temp ^ *maskpoint;
  fprintf (fl,"z = %3d   :  d = DATA xor MASK = %3d xor %3d = %3d\n\r",z, *temp, *maskpoint, d);
  while (d > 255) d -= 256;
  d *= enn;
  d_address = enb + d;

  maskpoint -= 10;
  temp = dataval + w;
  c = *temp ^ *maskpoint;
  fprintf (fl,"w = %3d   :  c = DATA xor MASK = %3d xor %3d = %3d\n\r", w, *temp, *maskpoint, c);
  while (c > 255) c -= 256;
  c *= enn;
  c_address = enb + c;


  fprintf (fl, "DATA BEFORE RIGHT ENCLAVE : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r");
  inverse_right_enclave (c_address, d_address, dataval);
  fprintf (fl, "DATA  AFTER RIGHT ENCLAVE : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r\n\r");

  maskpoint -= 10;

  temp = dataval + 5 + z;
  b = *temp ^ *maskpoint;
  fprintf (fl,"z = %3d   :  b = DATA xor MASK = %3d xor %3d = %3d\n\r", z, *temp, *maskpoint, b);
  while (b > 255) b -= 256;
  b *= enn;
  b_address = enb + b;

  maskpoint -= 10;
  temp = dataval + 5 + w;
  a = *temp ^ *maskpoint;
  fprintf (fl,"w = %3d   :  a = DATA xor MASK = %3d xor %3d = %3d\n\r", w, *temp, *maskpoint, a);
  while (a > 255) a -= 256;
  a *= enn;
  a_address = enb + a;

  fprintf (fl, "DATA BEFORE LEFT  ENCLAVE : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r");
  inverse_left_enclave (a_address, b_address, dataval);
  fprintf (fl, "DATA  AFTER LEFT  ENCLAVE : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r\n\r");

  datapoint = dataval + 9;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  fprintf (fl," keytable = DATA xor MASK = %3d xor %3d = %3d", *datapoint, *maskpoint, table);
  table *= 10;
  taddress = keyval + table;

  fprintf (fl, "DATA BEFORE KEY XOR     : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r");
  key_xor (skip1, taddress, dataval);
  fprintf (fl, "DATA  AFTER KEY XOR     : ");
  for (pi = 0; pi <= 9; ++pi) fprintf (fl,"%4d",*(dataval+pi));
  fprintf (fl, "\n\r\n\r");

  datapoint = dataval;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  while (table > 15) table -= 16;
  table *= isn;
  taddress = isb + table;
  substitute (skip2, taddress, dataval);

  datapoint = dataval + 9;
  maskpoint -= 10;

  table = *datapoint ^ *maskpoint;
  while (table > 15) table -= 16;
  table *= isn;
  taddress = isb + table;
  substitute (skip1, taddress, dataval);

  --datapoint;
  maskpoint += 79;

  for (round = 8; round >= 0; --round)
  {  skip1 = round;
     skip2 = round + 1;

    table = 0;
    temp = dataval;

    for (fi = 0; fi <= 9; ++fi)
    { table ^= *temp;
      ++temp;
    }
    table ^= *maskpoint;
    while (table > 255) table -= 256;
    table *= pen;
    taddress = peb + table;
    inverse_permutate (taddress, dataval);

    datapoint = dataval + skip2;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    table *= 10;
    taddress = keyval + table;
    key_xor (skip2, taddress, dataval);

    w = round - 1;
    while (w < 0) w += 5;
    while (w > 4) w -= 5;
    z = w + 1;
    while (z > 4) z -= 5;

    maskpoint -= 10;
    temp = dataval + z;
    d = *temp ^ *maskpoint;
    while (d > 255) d -= 256;
    d *= enn;
    d_address = enb + d;

    maskpoint -= 10;
    temp = dataval + w;
    c = *temp ^ *maskpoint;
    while (c > 255) c -= 256;
    c *= enn;
    c_address = enb + c;

    inverse_right_enclave (c_address, d_address, dataval);

    maskpoint -= 10;
    temp = dataval + 5 + z;
    b = *temp ^ *maskpoint;
    while (b > 255) b -= 256;
    b *= enn;
    b_address = enb + b;

    maskpoint -= 10;
    temp = dataval + 5 + w;
    a = *temp ^ *maskpoint;
    while (a > 255) a -= 256;
    a *= enn;
    a_address = enb + a;

    inverse_left_enclave (a_address, b_address, dataval);

    datapoint = dataval + skip1;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    table *= 10;
    taddress = keyval + table;
    key_xor (skip1, taddress, dataval);

    datapoint = dataval + skip2;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= isn;
    taddress = isb + table;
    substitute (skip2, taddress, dataval);

    datapoint = dataval + skip1;
    maskpoint -= 10;

    table = *datapoint ^ *maskpoint;
    while (table > 15) table -= 16;
    table *= isn;
    taddress = isb + table;
    substitute (skip1, taddress, dataval);

    --datapoint;
    maskpoint += 79;
  }

  fclose (fl);

  return (0);

}


int create_function_tables (peb, sub, isb, enb, pen, sun, cimp)
  byte	*peb, *sub, *isb, *enb;
  int	pen, sun;
  byte	*cimp;
{
  create_permutations (256, peb, pen, cimp);
  create_substitutions (16, sub, sun, cimp);
  create_inverse_substitutions (16, sub, isb, sun);
  create_enclaves (256, enb, cimp);

  return (0);
}




int main ()
{
  int   i, ii;

  create_function_tables (&permtable, &esubtable, &dsubtable, &encltable,
			  10, 256, 32);

  create_key_table (&key_x, &key_y, &keystable, &permtable, &esubtable,
		    &encltable, 10, 256, 15);

  create_mask_table (&keystable, &masktable);

  e_redoc_ii (&keystable, &masktable, &dataval, &permtable, &esubtable,
	       &encltable, 10, 256, 15, 10);

  d_redoc_ii (&keystable, &masktable, &dataval, &permtable, &dsubtable,
	       &encltable, 10, 256, 15);

  return (0);
}

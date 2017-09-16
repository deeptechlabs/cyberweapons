

/* Do not modify this file; it is automatically generated
   from hash.in and haval.c
 */

/*
 *  hash.in : Generic framework for hash function extension modules
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
  
/* Basic object type */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef _HAVE_STDC_HEADERS
#include <string.h>
#endif

#define Py_USE_NEW_NAMES
#include "Python.h"
#include "modsupport.h"

       /* Endianness testing and definitions */
#define TestEndianness(variable) {int i=1; variable=BIG_ENDIAN;\
                                  if (*((char*)&i)==1) variable=LITTLE_ENDIAN;}

#define LITTLE_ENDIAN 1
#define BIG_ENDIAN 0

	/* This is where the actual code for the hash function will go */

#define PCTObject_HEAD PyObject_HEAD

/*
 *  haval.c : Implementation code for the HAVAL hash function
 *
 * Part of the Python Cryptography Toolkit, version 0.0.4
 *
 * Copyright (C) 1995, A.M. Kuchling
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */

#define VERSION 1		/* Version of HAVAL algorithm */

static int Endianness=-1;

typedef unsigned int U32;
typedef unsigned char U8;

#define rotate(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define f1(x6,x5,x4,x3,x2,x1,x0) ((x1&x4)^(x2&x5)^(x3&x6)^(x0&x1)^(x0))
#define f2(x6,x5,x4,x3,x2,x1,x0) ((x1&x2&x3) ^ (x2&x4&x5) ^ (x1&x2) ^ (x1&x4) \
				  ^ (x2&x6) ^ (x3&x5) ^ (x4&x5) ^ (x0&x2) ^ x0)
#define f3(x6,x5,x4,x3,x2,x1,x0) ((x1&x2&x3) ^ (x1&x4) ^ (x2&x5) ^ (x3&x6) \
				  ^ (x0&x3) ^ (x0))
#define f4(x6,x5,x4,x3,x2,x1,x0) ((x1&x2&x3) ^ (x2&x4&x5) ^ (x3&x4&x6) ^ \
				  (x1&x4) ^ (x2&x6) ^ (x3&x4) ^ (x3&x5) ^ \
				  (x3&x6) ^ (x4&x5) ^ (x4&x6) ^ (x0&x4) ^ \
				  (x0))
#define f5(x6,x5,x4,x3,x2,x1,x0) ((x1&x4) ^ (x2&x5) ^ (x3&x6) ^ (x0&x1&x2&x3) \
				  ^ (x0&x5) ^ (x0))

static int W2[32]={5,14,26,18,11,28,7,16,0,23,20,22,1,10,4,8,
		     30,3,21,9,17,24,29,6,19,12,15,13,2,25,31,27};
static int W3[32]={19,9,4,20,28,17,8,22,29,14,25,12,24,30,16,26,
		     31,15,7,3,1,0,18,27,13,6,21,10,23,11,5,2};
static int W4[32]={24,4,0,14,2,7,28,23,26,6,30,20,18,25,19,3,
		     22,11,31,21,8,27,12,9,1,29,5,15,17,10,16,13};
static int W5[32]={27,3,21,26,17,11,20,29,19,0,12,7,13,8,31,10,
		     5,9,14,30,18,6,28,24,2,23,16,22,4,1,25,15};
static U32 K2[32]={0x452821E6U, 0x38D01377U, 0xBE5466CFU, 0x34E90C6CU, 0xC0AC29B7U, 
		     0xC97C50DDU, 0x3F84D5B5U, 0xB5470917U, 0x9216D5D9U, 0x8979FB1BU, 
		     0xD1310BA6U, 0x98DFB5ACU, 0x2FFD72DBU, 0xD01ADFB7U, 0xB8E1AFEDU, 
		     0x6A267E96U, 0xBA7C9045U, 0xF12C7F99U, 0x24A19947U, 0xB3916CF7U, 
		     0x0801F2E2U, 0x858EFC16U, 0x636920D8U, 0x71574E69U, 0xA458FEA3U, 
		     0xF4933D7EU, 0x0D95748FU, 0x728EB658U, 0x718BCD58U, 0x82154AEEU, 
		     0x7B54A41DU, 0xC25A59B5};
static U32 K3[32]={0x9C30D539U, 0x2AF26013U, 0xC5D1B023U, 0x286085F0U, 0xCA417918U, 
		     0xB8DB38EFU, 0x8E79DCB0U, 0x603A180EU, 0x6C9E0E8BU, 0xB01E8A3EU, 
		     0xD71577C1U, 0xBD314B27U, 0x78AF2FDAU, 0x55605C60U, 0xE65525F3U, 
		     0xAA55AB94U, 0x57489862U, 0x63E81440U, 0x55CA396AU, 0x2AAB10B6U, 
		     0xB4CC5C34U, 0x1141E8CEU, 0xA15486AFU, 0x7C72E993U, 0xB3EE1411U, 
		     0x636FBC2AU, 0x2BA9C55DU, 0x741831F6U, 0xCE5C3E16U, 0x9B87931EU, 
		     0xAFD6BA33U, 0x6C24CF5CU};
static U32 K4[32]={0x7A325381U, 0x28958677U, 0x3B8F4898U, 0x6B4BB9AFU, 0xC4BFE81BU, 0x66282193U, 0x61D809CCU, 0xFB21A991U, 0x487CAC60U, 0x5DEC8032U, 0xEF845D5DU, 0xE98575B1U, 0xDC262302U, 0xEB651B88U, 0x23893E81U, 0xD396ACC5U, 0x0F6D6FF3U, 0x83F44239U, 0x2E0B4482U, 0xA4842004U, 0x69C8F04AU, 0x9E1F9B5EU, 0x21C66842U, 0xF6E96C9AU, 0x670C9C61U, 0xABD388F0U, 0x6A51A0D2U, 0xD8542F68U, 0x960FA728U, 0xAB5133A3U, 0x6EEF0B6CU, 0x137A3BE4U};
static U32 K5[32]={0xBA3BF050U, 0x7EFB2A98U, 0xA1F1651DU, 0x39AF0176U, 0x66CA593EU, 0x82430E88U, 0x8CEE8619U, 0x456F9FB4U, 0x7D84A5C3U, 0x3B8B5EBEU, 0xE06F75D8U, 0x85C12073U, 0x401A449FU, 0x56C16AA6U, 0x4ED3AA62U, 0x363F7706U, 0x1BFEDF72U, 0x429B023DU, 0x37D0D724U, 0xD00A1248U, 0xDB0FEAD3U, 0x49F1C09BU, 0x075372C9U, 0x80991B7BU, 0x25D479D8U, 0xF6E8DEF7U, 0xE3FE501AU, 0xB6794C3BU, 0x976CE0BDU, 0x04C006BAU, 0xC1A94FB6U, 0x409F60C4U};

enum ePASS {P3=3, P4=4, P5=5};
enum eFPTLEN {L128=128, L160=160, L192=192, L224=224, L256=256};
 
typedef struct {
  PCTObject_HEAD
 U32 D[8], msglen1, msglen2;
 U8 buf[128];
 int buflen;
 enum eFPTLEN FPTLEN;
 enum ePASS PASS;
} HAVALobject;


static void HV_Hash(s, D, buf)
     HAVALobject *s;
     U32 *D;
     U8 *buf;
{
 U32 temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;
 U32 w[32];
 int i, j;

 for(i=0, j=0; i<32; i++,j+=4) 
   w[i]=buf[j]+(buf[j+1]<<8)+(buf[j+2]<<16)+(buf[j+3]<<24);

 /* e1 = H1(D, B) */
 
 temp0=D[0]; temp1=D[1]; temp2=D[2]; temp3=D[3]; temp4=D[4]; temp5=D[5]; temp6=D[6]; temp7=D[7];
 for(i=0; i<32; i++) 
   {
    U32 P, R;
    
    switch(s->PASS) 
      {
     case(P3):
       P=f1(temp1, temp0, temp3, temp5, temp6, temp2, temp4);
       break;
     case(P4):
       P=f1(temp2, temp6, temp1, temp4, temp5, temp3, temp0);
       break;
     case(P5):
       P=f1(temp3, temp4, temp1, temp0, temp5, temp2, temp6);
       break;
      }
    R=rotate(P,7) + rotate(temp7,11) + w[i];
    temp7=temp6; temp6=temp5; temp5=temp4; temp4=temp3; 
    temp3=temp2; temp2=temp1; temp1=temp0; temp0=R;
   }
 
 /* e2 = H2(e1, B) */

 for(i=0; i<32; i++) 
   {
    U32 P,R;
    switch(s->PASS) 
      {
     case(P3):
       P=f2(temp4, temp2, temp1, temp0, temp5, temp3, temp6);
       break;
     case(P4):
       P=f2(temp3, temp5, temp2, temp0, temp1, temp6, temp4);
       break;
     case(P5):
       P=f2(temp6, temp2, temp1, temp0, temp3, temp4, temp5);
       break;
      }
    R=rotate(P, 7) + rotate(temp7, 11) + K2[i]+ w[W2[i]];
    temp7=temp6; temp6=temp5; temp5=temp4; temp4=temp3; 
    temp3=temp2; temp2=temp1; temp1=temp0; temp0=R;
   }
 
 /* e3 = H3(e2, B) */
 
 for(i=0; i<32; i++) 
   {
    U32 P,R;
    switch(s->PASS) 
      {
     case(P3):
       P=f3(temp6, temp1, temp2, temp3, temp4, temp5, temp0);
       break;
     case(P4):
       P=f3(temp1, temp4, temp3, temp6, temp0, temp2, temp5);
       break;
     case(P5):
       P=f3(temp2, temp6, temp0, temp4, temp3, temp1, temp5);
       break;
      }
    R=rotate(P, 7) + rotate(temp7, 11) + K3[i]+ w[W3[i]];
    temp7=temp6; temp6=temp5; temp5=temp4; temp4=temp3; 
    temp3=temp2; temp2=temp1; temp1=temp0; temp0=R;
   }
 
 if (s->PASS==P3)		/* Final output */
   {
    D[0]+=temp0; D[1]+=temp1; D[2]+=temp2; D[3]+=temp3; 
    D[4]+=temp4; D[5]+=temp5; D[6]+=temp6; D[7]+=temp7; 
    return;    
   }

 /* e4 = H4(e3, B) */
 for(i=0; i<32; i++) 
   {
    U32 P,R;
    switch(s->PASS) 
      {
     case(P4):
       P=f4(temp6, temp4, temp0, temp5, temp2, temp1, temp3);
       break;
     case(P5):
       P=f4(temp1, temp5, temp3, temp2, temp0, temp4, temp6);
       break;
      }
    R=rotate(P, 7) + rotate(temp7, 11) + K4[i]+ w[W4[i]];
    temp7=temp6; temp6=temp5; temp5=temp4; temp4=temp3; 
    temp3=temp2; temp2=temp1; temp1=temp0; temp0=R;
   }
 
 if (s->PASS==P4)		/* Final output */
   {
    D[0]+=temp0; D[1]+=temp1; D[2]+=temp2; D[3]+=temp3; 
    D[4]+=temp4; D[5]+=temp5; D[6]+=temp6; D[7]+=temp7; 
    return;
   }

 /* e5 = H5(e4, B) */

 for(i=0; i<32; i++) 
   {
    U32 P,R;
    P=f5(temp2, temp5, temp0, temp6, temp4, temp3, temp1);
    R=rotate(P, 7) + rotate(temp7, 11) + K5[i]+ w[W5[i]];
    temp7=temp6; temp6=temp5; temp5=temp4; temp4=temp3; 
    temp3=temp2; temp2=temp1; temp1=temp0; temp0=R;
   }
 D[0]+=temp0; D[1]+=temp1; D[2]+=temp2; D[3]+=temp3; 
 D[4]+=temp4; D[5]+=temp5; D[6]+=temp6; D[7]+=temp7; 
 return;    
} 

static void HAVALinit (s)
     HAVALobject *s;                         /* context */
{
 if (Endianness==-1) TestEndianness(Endianness);
 s->buflen=0;
 s->msglen1=s->msglen2=0;
 s->D[0]=0x243f6a88U;
 s->D[1]=0x85a308d3U;
 s->D[2]=0x13198a2eU;
 s->D[3]=0x03707344U;
 s->D[4]=0xa4093822U;
 s->D[5]=0x299f31d0U;
 s->D[6]=0x082efa98U;
 s->D[7]=0xec4e6c89U;
}

static void HAVALupdate (s, buf, len)
HAVALobject *s;
U8 *buf;                                /* input block */
unsigned int len;                     /* length of input block */
{
 int temp;

 temp=s->msglen2;
 s->msglen2+=len*8;
 if (s->msglen2<temp) /* Did an overflow occur on the 32-bit msg length? */
   {
    s->msglen1++;
   }
 while (len>0) 
   {
    temp = ((128-s->buflen)>len) ? len : 128-s->buflen;
    memcpy(s->buf+s->buflen, buf, temp);
    len-=temp;
    buf+=temp; 
    s->buflen+=temp;
    if (s->buflen==128) 
      {
       HV_Hash(s, s->D, s->buf); s->buflen=0;
      }
   }
}

static PyObject *HAVALdigest (s)
     HAVALobject *s;
{
 int i, j;
 U32 value, D[8];
 U8 buf[128];
 for(i=0; i<8; i++) D[i]=s->D[i];

 i=s->buflen;
 memcpy(buf, s->buf, i);
 buf[i++]=128; 
 if (i>944/8) 
   {
    memset(buf+i, 0, 128-i);
    HV_Hash(s, D, buf); 
    i=0;
   }
 memset(buf+i, 0, 944/8-i);
 i=944/8;
 value=VERSION | (s->PASS<<3) | (s->FPTLEN<<6);
 buf[i++]=value & 0xff;
 buf[i++]=(value >> 8) & 0xff; 

 /* Append the message length */
 buf[i++]=(s->msglen2       ) & 0xff; 
 buf[i++]=(s->msglen2 >>  8 ) & 0xff; 
 buf[i++]=(s->msglen2 >> 16 ) & 0xff; 
 buf[i++]=(s->msglen2 >> 24 ) & 0xff;        

 buf[i++]=(s->msglen1       ) & 0xff; 
 buf[i++]=(s->msglen1 >>  8 ) & 0xff; 
 buf[i++]=(s->msglen1 >> 16 ) & 0xff; 
 buf[i++]=(s->msglen1 >> 24 ) & 0xff;        
 
 HV_Hash(s, D, buf); 
 
 /* Tailor the output to the appropriate length */
/* 256-byte output
   D[0]=0xac869783U; D[1]=0x6aee894fU; D[2]=0x65207fe8U; D[3]=0x971068acU;
 D[4]=0x996a27d7U; D[5]=0x72e9b703U; D[6]=0x6d5692e9U; D[7]=0xc8ee30dU;  */
/* 128-byte output 
 D[0]=0xd7b8185dU; D[1]=0x59d1f164U; D[2]=0x87bba84dU; D[3]=0x4b7f55dcU; 
 D[4]=0xbcc5be6bU; D[5]=0xbbc32906U; D[6]=0x9dabd130U; D[7]=0x3bde9293U; */

 if (s->FPTLEN==128) 
   {
    D[3] +=  (D[7] & 0xff000000U) | (D[6] & 0x00ff0000U) | 
             (D[5] & 0x0000ff00U) | (D[4] & 0x000000ffU);
    D[2] +=  ((
	       (D[7] & 0x00ff0000U) | (D[6] & 0x0000ff00U) |
	       (D[5] & 0x000000ffU)
	      )<<8) | ((D[4] & 0xff000000U)>>24);
    D[1] +=  ((
	       (D[7] & 0x0000ff00U) | (D[6] & 0x000000ffU)
	      )<<16) |
	     ((
	       (D[5] & 0xff000000U) | (D[4] & 0x00ff0000U)
	      )>>16);
    D[0] += 
	     ((
	        D[7] & 0x000000ffU
	      )<<24) |
	     ((
	       (D[6] & 0xff000000U) | (D[5] & 0x00ff0000U) |
	       (D[4] & 0x0000ff00U)
	      )>>8);
   }
 if (s->FPTLEN==L160) 
   {
    D[4] +=  ((D[7] & 0xfe000000U) | (D[6] & 0x01f80000U) | 
	      (D[5] & 0x0007f000U)) >>12;
    D[3] +=  ((D[7] & 0x01f80000U) |  (D[6] & 0x0007f000U) |
	      (D[5] & 0x00000fc0U)) >> 6;
    D[2] +=  ((D[7] & 0x0007f000U) |  (D[6] & 0x00000fc0U) |
	      (D[5] & 0x0000003fU))     ;
    D[1] +=  (((D[7] & 0x00000fc0U) | (D[6] & 0x0000003fU)) <<7) |
              ((D[5] & 0xfe000000U)>>25);
    D[0] +=  (((D[6] & 0xfe000000U) | (D[5] & 0x01f80000U)) >>19) |
              ((D[7] & 0x0000003fU)<<13);
   }
 if (s->FPTLEN==L192) 
   {
    D[5] +=   ((D[7] & 0xfc000000U) | (D[6] & 0x03e00000U)) >> 21;
    D[4] +=   ((D[7] & 0x03e00000U) | (D[6] & 0x001f0000U)) >> 16;
    D[3] +=   ((D[7] & 0x001f0000U) | (D[6] & 0x0000fc00U)) >> 10;
    D[2] +=   ((D[7] & 0x0000fc00U) | (D[6] & 0x000003e0U)) >>  5;
    D[1] +=   ((D[7] & 0x000003e0U) | (D[6] & 0x0000001fU))      ;
    D[0] +=   ((D[7] & 0x0000001fU)<<6) | ((D[6] & 0xfc000000U) >>26);
   }
 if (s->FPTLEN==L224) 
   {
    D[6] +=    (D[7] & 0x0000000fU);
    D[5] +=    (D[7] & 0x000001f0U) >>  4;
    D[4] +=    (D[7] & 0x00001e00U) >>  9;
    D[3] +=    (D[7] & 0x0003e000U) >> 13;
    D[2] +=    (D[7] & 0x003c0000U) >> 18;
    D[1] +=    (D[7] & 0x07c00000U) >> 22;
    D[0] +=    (D[7] & 0xf8000000U) >> 27;
   }
 for(i=0,j=0; i<s->FPTLEN/32; i++) 
   {
    buf[j++]=D[i] & 0xff; D[i] >>= 8;
    buf[j++]=D[i] & 0xff; D[i] >>= 8;
    buf[j++]=D[i] & 0xff; D[i] >>= 8;
    buf[j++]=D[i] & 0xff;        
   }
 return PyString_FromStringAndSize((unsigned char *)buf, s->FPTLEN/8);
}


static void
HAVALcopy(src, dest)
     HAVALobject *src, *dest;
{
  int i;
  dest->buflen =src->buflen;
  dest->msglen1=src->msglen1;
  dest->msglen2=src->msglen2;
  dest->PASS   =src->PASS;
  dest->FPTLEN =src->FPTLEN;
  memcpy(dest->buf, src->buf, src->buflen);
  
  for(i=0; i<8; i++) dest->D[i]=src->D[i];
}
 	

staticforward PyTypeObject HAVALtype;

#define is_HAVALobject(v) ((v)->ob_type == &HAVALtype)

static HAVALobject *
newHAVALobject()
{
	HAVALobject *HAVALptr;

	HAVALptr = PyObject_NEW(HAVALobject, &HAVALtype);
	if (HAVALptr == NULL)
		return NULL;

	HAVALinit(HAVALptr);
	return HAVALptr;
}

/* Internal methods for a hashing object */

static void
HAVAL_dealloc(ptr)
	PyObject *ptr;
{
	HAVALobject *HAVALptr=(HAVALobject *)ptr;
	PyMem_DEL(HAVALptr);
}


/* External methods for a hashing object */

static PyObject *
HAVAL_copy(self, args)
	HAVALobject *self;
	PyObject *args;
{
	HAVALobject *newobj;

	if (!PyArg_NoArgs(args))
		return(NULL);

	if ( (newobj = newHAVALobject())==NULL)
		return(NULL);

	HAVALcopy(self, newobj);
	return((PyObject *)newobj); 
}

static PyObject *
HAVAL_digest(self, args)
	HAVALobject *self;
	PyObject *args;
{

	if (!PyArg_NoArgs(args))
		return NULL;

	return (PyObject *)HAVALdigest(self);
}

static PyObject *
HAVAL_update(self, args)
	HAVALobject *self;
	PyObject *args;
{
	unsigned char *cp;
	int len;

	if (!PyArg_Parse(args, "s#", &cp, &len))
		return NULL;

	HAVALupdate(self, cp, len);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef HAVAL_methods[] = {
	{"copy",		(PyCFunction)HAVAL_copy},
	{"digest",		(PyCFunction)HAVAL_digest},
	{"update",		(PyCFunction)HAVAL_update},
	{NULL,			NULL}		/* sentinel */
};

static PyObject *
HAVAL_getattr(self, name)
	HAVALobject *self;
	char *name;
{
	if (strcmp(name, "blocksize")==0)
	  return PyInt_FromLong(1);
	if (strcmp(name, "digestsize")==0)
	  return PyInt_FromLong(self->FPTLEN);
	if (strcmp(name, "passes")==0)
	  return PyInt_FromLong(self->PASS);
	
	return Py_FindMethod(HAVAL_methods, (PyObject *)self, name);
}

static PyTypeObject HAVALtype = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,			/*ob_size*/
	"HAVAL",			/*tp_name*/
	sizeof(HAVALobject),	/*tp_size*/
	0,			/*tp_itemsize*/
	/* methods */
	HAVAL_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	HAVAL_getattr, /*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
        0,			/*tp_as_number*/
};


/* The single module-level function: new() */

static PyObject *
HAVAL_new(self, args)
	PyObject *self;
	PyObject *args;
{
	HAVALobject *HAVALptr;
	unsigned char *cp = NULL;
	int len, pass=P5, fptlen=L256;

	if (!PyArg_ParseTuple(args, "s#|ii", &cp, &len, &pass, &fptlen))
	  {
	   PyErr_Clear();
	   if (!PyArg_ParseTuple(args, "")) return NULL;
	  }

	if ((HAVALptr = newHAVALobject()) == NULL)
		return NULL;

	HAVALptr->PASS=pass;
	HAVALptr->FPTLEN=fptlen;
	
	if (cp)
		HAVALupdate(HAVALptr, cp, len);

	return (PyObject *)HAVALptr;
}


/* List of functions exported by this module */

static struct PyMethodDef HAVAL_functions[] = {
	{"new",			(PyCFunction)HAVAL_new, 1},
	{"haval",		(PyCFunction)HAVAL_new, 1},
	{NULL,			NULL}		 /* Sentinel */
};


/* Initialize this module. */

#define insint(n,v) {PyObject *o=PyInt_FromLong(v); if (o!=NULL) {PyDict_SetItemString(d,n,o); Py_DECREF(o);}}

void
inithaval()
{
	PyObject *d, *m;

	m = Py_InitModule("haval", HAVAL_functions);

	 /* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);
	insint("blocksize", 1);  /* For future use, in case some hash
			    functions require an integral number of
			    blocks */ 
/* insint("digestsize", 32); /* Digest size is object-dependent for HAVAL */

 /* Check for errors */
 if (PyErr_Occurred())
  Py_FatalError("can't initialize module haval");
}



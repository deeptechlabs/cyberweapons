/* DESC.C - Data Encryption Standard routines for RSAREF
     Based on "Karn/Hoey/Outerbridge" implementation (KHODES)
 */

#include "global.h"
#include "rsaref.h"
#include "des.h"

static void Copy8 PROTO_LIST ((unsigned char *, unsigned char *));
static void DESKey PROTO_LIST ((UINT4 *, unsigned char *, UINT2));
static void DESFunction PROTO_LIST ((UINT4 *, UINT4 *));

#define Unpack(a,b) Copy8((a), (unsigned char *)(b))
#define Pack(a,b) Copy8((unsigned char *)(a), (b))

/* Initialize context.  Caller must zeroize the context when finished.
 */
void DES_CBCInit (context, key, iv, encrypt)
DES_CBC_CTX *context;                                            /* context */
unsigned char key[8];                                                /* key */
unsigned char iv[8];                                 /* initializing vector */
int encrypt;                     /* encrypt flag (1 = encrypt, 0 = decrypt) */
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;

  /* Pack initializing vector into context.
   */
  Pack (context->iv, iv);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];

  /* Precompute key schedule
   */
  DESKey (context->subkeys, key, (UINT2)(encrypt ? 1 : 0));
}

/* DES-CBC block update operation. Continues a DES-CBC encryption
   operation, processing eight-byte message blocks, and updating
   the context.
 */
int DES_CBCUpdate (context, output, input, len)
DES_CBC_CTX *context;                                            /* context */
unsigned char *output;                                      /* output block */
unsigned char *input;                                        /* input block */
unsigned int len;                      /* length of input and output blocks */
{
  UINT4 inputBlock[2], work[2];
  unsigned int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
        
    /* Chain if encrypting.
     */
    if (context->encrypt) {
      work[0] = inputBlock[0] ^ context->iv[0];
      work[1] = inputBlock[1] ^ context->iv[1];
    }
    else {
      work[0] = inputBlock[0];
      work[1] = inputBlock[1];         
    }

    DESFunction (work, context->subkeys);

    /* Chain if decrypting, then update IV.
     */
    if (context->encrypt) {
      context->iv[0] = work[0];
      context->iv[1] = work[1];
    }
    else {
      work[0] ^= context->iv[0];
      work[1] ^= context->iv[1];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
    }
    Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  
  return (0);
}

void DES_CBCRestart (context)
DES_CBC_CTX *context;
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
}

/* Initialize context.  Caller must zeroize the context when finished.
   The key has the DES key, input whitener and output whitener concatenated.
 */
void DESX_CBCInit (context, key, iv, encrypt)
DESX_CBC_CTX *context;
unsigned char key[24];                              /* DES key and whiteners */
unsigned char iv[8];                              /* DES initializing vector */
int encrypt;                      /* encrypt flag (1 = encrypt, 0 = decrypt) */
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;

  /* Pack initializing vector and whiteners into context.
   */
  Pack (context->iv, iv);
  Pack (context->inputWhitener, key + 8);
  Pack (context->outputWhitener, key + 16);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];

  /* Precompute key schedule.
   */
  DESKey (context->subkeys, key, (UINT2)(encrypt ? 1 : 0));
}

/* DESX-CBC block update operation. Continues a DESX-CBC encryption
   operation, processing eight-byte message blocks, and updating
   the context.
 */
int DESX_CBCUpdate (context, output, input, len)
DESX_CBC_CTX *context;                                           /* context */
unsigned char *output;                                      /* output block */
unsigned char *input;                                        /* input block */
unsigned int len;                      /* length of input and output blocks */
{
  UINT4 inputBlock[2], work[2];
  unsigned int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++)  {
    Pack (inputBlock, &input[8*i]);
        
    /* Chain if encrypting, and xor with whitener.
     */
    if (context->encrypt) {
      work[0] =
        inputBlock[0] ^ context->iv[0] ^ context->inputWhitener[0];
      work[1] =
        inputBlock[1] ^ context->iv[1] ^ context->inputWhitener[1];
    }
    else {
      work[0] = inputBlock[0] ^ context->outputWhitener[0];
      work[1] = inputBlock[1] ^ context->outputWhitener[1];         
    }

    DESFunction (work, context->subkeys);

    /* Xor with whitener, chain if decrypting, then update IV.
     */
    if (context->encrypt) {
      work[0] ^= context->outputWhitener[0];
      work[1] ^= context->outputWhitener[1];
      context->iv[0] = work[0];
      context->iv[1] = work[1];
    }
    else {
      work[0] ^= context->iv[0] ^ context->inputWhitener[0];
      work[1] ^= context->iv[1] ^ context->inputWhitener[1];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
    }
    Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  
  return (0);
}

void DESX_CBCRestart (context)
DESX_CBC_CTX *context;
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
}

/* Initialize context.  Caller must zeroize the context when finished.
 */
void DES3_CBCInit(context, key, iv, encrypt)
DES3_CBC_CTX *context;                                           /* context */
unsigned char key[24];                                               /* key */
unsigned char iv[8];                                 /* initializing vector */
int encrypt;                     /* encrypt flag (1 = encrypt, 0 = decrypt) */
{  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;

  /* Pack initializing vector into context.
   */
  Pack (context->iv, iv);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];

  /* Precompute key schedules.
   */
  if( encrypt ) {
  	DESKey (context->subkeys[0], key, 1);
  	DESKey (context->subkeys[1], &key[8], 0);
  	DESKey (context->subkeys[2], &key[16], 1);
	}
  else {
    DESKey (context->subkeys[0], &key[16], 0);
  	DESKey (context->subkeys[1], &key[8], 1);
  	DESKey (context->subkeys[2], key, 0);
  	}
  return;
}

int DES3_CBCUpdate (context, output, input, len)
DES3_CBC_CTX *context;                                           /* context */
unsigned char *output;                                      /* output block */
unsigned char *input;                                        /* input block */
unsigned int len;                      /* length of input and output blocks */
{
  UINT4 inputBlock[2], work[2];
  unsigned int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    Pack (inputBlock, &input[8*i]);
        
    /* Chain if encrypting.
     */
    if (context->encrypt) {
      work[0] = inputBlock[0] ^ context->iv[0];
      work[1] = inputBlock[1] ^ context->iv[1];
    }
    else {
      work[0] = inputBlock[0];
      work[1] = inputBlock[1];         
    }

    DESFunction (work, context->subkeys[0]);
    DESFunction (work, context->subkeys[1]);
    DESFunction (work, context->subkeys[2]);

    /* Chain if decrypting, then update IV.
     */
    if (context->encrypt) {
      context->iv[0] = work[0];
      context->iv[1] = work[1];
    }
    else {
      work[0] ^= context->iv[0];
      work[1] ^= context->iv[1];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
    }
    Unpack (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  
  return (0);
}

void DES3_CBCRestart (context)
DES3_CBC_CTX *context;
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
}

static void Copy8(into, outof)
unsigned char *into;
unsigned char *outof;
{
asm {
	movea.l	outof,a0
	movea.l	into,a1
	move.b	(a0)+,(a1)+
	move.b	(a0)+,(a1)+
	move.b	(a0)+,(a1)+
	move.b	(a0)+,(a1)+
	move.b	(a0)+,(a1)+
	move.b	(a0)+,(a1)+
	move.b	(a0)+,(a1)+
	move.b	(a0),(a1)
	}
return;
}

static void DESKey (subkeys, key, encrypt)
UINT4 subkeys[32];
unsigned char key[8];
UINT2 encrypt;
{
asm {
		movem.l d3-d5/a2-a3,-(a7)	;save registers
		lea		@kpp,a2			;table of key bit permutations
		lea		@kp0,a0			;table of permutation offsets
		movea.l	subkeys,a3
		movea.l key,a1			;load address of nominal key
		moveq	#0,d4			;clear this register
		moveq	#15,d0			;do all 16 rounds
		cmpi.w	#0,encrypt
		bne		@cks1			;ne.Z, hence encrypt
		adda.w	#120,a3
		bra		@cks1			;now start

@kpp:	dc.w	0,0,0,112,112,112,112,112,224,0,112,112,112,112,112,224

@kp0:	dc.b	6,6,1,6,6,5,4,6,7,4,6,7,2,7,1,5,0,5,4,5,3,6,3,7,5,4,7,6
		dc.b	0,1,2,2,3,4,4,1,6,2,4,3,0,4,0,2,7,3,2,3,4,2,7,1,1,1,2,4
		dc.b	5,5,4,7,7,7,0,6,1,7,2,5,5,6,6,4,7,5,0,7,4,4,3,5,2,6,5,7
		dc.b	5,2,5,1,3,2,0,3,6,3,2,1,3,3,1,4,5,3,1,2,1,3,7,2,6,1,3,1
		
		dc.b	4,0,4,3,4,6,1,3,5,6,5,0,4,2,1,5,0,2,5,2,5,1,0,0,5,3,0,6
		dc.b	7,2,7,4,3,0,7,0,6,6,6,0,3,2,3,5,6,2,7,3,6,4,7,1,2,6,7,6
		dc.b	1,4,1,2,0,1,5,5,5,4,1,6,0,3,1,1,0,4,1,0,4,4,4,1,0,5,4,5
		dc.b	3,3,2,3,2,5,2,4,7,5,3,1,3,4,2,0,2,1,3,6,6,3,2,2,6,5,6,1
	
		dc.b	0,3,5,5,1,4,5,1,1,1,4,5,5,4,0,2,5,6,4,1,0,5,4,2,4,4,4,0
		dc.b	2,2,3,6,7,6,6,1,3,3,3,4,7,1,6,2,7,5,6,3,2,5,6,5,7,2,2,0
		dc.b	5,2,0,0,5,0,0,4,1,0,1,5,1,3,5,3,4,6,0,6,0,1,1,6,4,3,1,2
		dc.b	6,4,7,0,7,4,3,0,2,1,2,6,7,3,3,2,6,0,3,5,2,4,6,6,2,3,3,1

@cks1:	suba.w	(a2)+,a0			;correct permutation
		moveq	#7,d1				;do 8 bytes worth
@cks2:	moveq	#6,d2				;do 7 bits per byte
		moveq	#0,d3				;clear a byte to fill
@cks3:	move.b	(a0)+,d4			;get a byte number
		move.b	(a0)+,d5			;get a bit offset
		btst	d5,0(a1,d4.w)		;test bit in key byte
		beq.s	@cks4				;if no bit to set
		bset	d2,d3				;else set a bit
@cks4:	dbf		d2,@cks3			;loop until all bits done
		move.b	d3,(a3)+			;set byte
		dbf		d1,@cks2			;loop through all bytes
		lea		-8(a3),a1			;reset a1 to last subkey
		cmpi.w	#0,encrypt
		bne.s	@cks5				;ne.Z, hence encrypt
		suba.w	#16,a3				;adjust filling
@cks5:	dbf		d0,@cks1			;and all rounds
		move.l	#0x3f3f3f3f,d1		;load bit mask
		movea.l	subkeys,a0			;load key register
		moveq	#15,d3				;load loop index
@cks6:	move.l	(a0),d0				;next raw target
		and.l	d1,d0				;clear bits
		rol.l	#4,d0				;preallign
		move.l	d0,(a0)+			;set cooked key - even
		move.l	(a0),d0				;next raw target
		and.l	d1,d0				;clear bits
		move.l	d0,(a0)+			;set cooked key - odd
		dbf		d3,@cks6			;all 64 longs
		movem.l (a7)+,d3-d5/a2-a3	;restore registers
		}         
return;
}

static void DESFunction (block, subkeys)
UINT4 *block;
UINT4 *subkeys;
{
asm {	movem.l d3-d6/a2,-(a7)
		movea.l	block,a0
		move.l	(a0)+,d3	/* D3 = L */
		move.l	(a0),d5		/* D5 = R */
	
		move.l	d3,d2		/* EXSHMSK(R,0x0f0f0f0f,L,4,tmp) */
		lsr.l	#4,d2
		eor.l	d5,d2
		andi.l	#0x0f0f0f0f,d2
		eor.l	d2,d5
		lsl.l	#4,d2
		eor.l	d2,d3
		swap	d3			/* EXSHMSK(R,0x0000ffff,L,16,tmp) */
		move.w	d3,d2
		move.w	d5,d3
		move.w	d2,d5
		swap	d3
		move.l	d5,d2		/* EXSHMSK(L,0x33333333,R,2,tmp) */
		lsr.l	#2,d2
		eor.l	d3,d2
		andi.l	#0x33333333,d2
		eor.l	d2,d3
		lsl.l	#2,d2
		eor.l	d2,d5
		move.l	d5,d2		/* EXSHMSK(L,0x00ff00ff,R,8,tmp) */
		lsr.l	#8,d2
		eor.l	d3,d2
		andi.l	#0x00ff00ff,d2
		eor.l	d2,d3
		lsl.l	#8,d2
		eor.l	d2,d5
		rol.l	#1,d5		/* EXSHMSK(R,0x55555555,L,1,tmp) */
		move.l	d3,d2
		eor.l	d5,d2
		andi.l	#0xaaaaaaaa,d2
		eor.l	d2,d5
		eor.l	d2,d3
		rol.l	#1,d3
	
		lea		@SP0,a0
		lea		@SP1,a1
		movea.l	subkeys,a2
		move.l	#0x03f003f0,d2
		moveq	#7,d1
		bra		@des1
		
		DC.W	0x0123	/* to force long allignment, if needed */
@SP0:	DC.L	0x01010400,0x00000208,0x00000100,0x00200000
		DC.L	0x00000000,0x08020200,0x02080100,0x04200002
		DC.L	0x00010000,0x00000000,0x02080000,0x04000802
		DC.L	0x01010404,0x08020008,0x42000100,0x00000000
		DC.L	0x01010004,0x08000200,0x00080000,0x00000800
		DC.L	0x00010404,0x00000000,0x00000100,0x04000802
		DC.L	0x00000004,0x00020208,0x40000000,0x00200802
		DC.L	0x00010000,0x08000200,0x02080000,0x04200800
		DC.L	0x00000400,0x00020008,0x40080100,0x04200802
		DC.L	0x01010400,0x08000008,0x00080000,0x00200000
		DC.L	0x01010404,0x08000008,0x02000100,0x00000000
		DC.L	0x00000400,0x00020000,0x40080100,0x04000002
		DC.L	0x01000404,0x08020208,0x42000100,0x00000002
		DC.L	0x01010004,0x00020008,0x42080000,0x04000000
		DC.L	0x01000000,0x08020000,0x00080100,0x04200002
		DC.L	0x00000004,0x00000208,0x40000000,0x00000802
		DC.L	0x00000404,0x08000000,0x02000000,0x04000800
		DC.L	0x01000400,0x00000008,0x40080000,0x00200802
		DC.L	0x01000400,0x08020200,0x40080000,0x00200002
		DC.L	0x00010400,0x00000200,0x00000000,0x04000800
		DC.L	0x00010400,0x00020200,0x40000100,0x04000002
		DC.L	0x01010000,0x08020000,0x42080100,0x04200000
		DC.L	0x01010000,0x08020008,0x42080100,0x04200800
		DC.L	0x01000404,0x00020208,0x02000100,0x00200002
		DC.L	0x00010004,0x08000208,0x42080000,0x04200000
		DC.L	0x01000004,0x00020200,0x40000100,0x00000800
		DC.L	0x01000004,0x00020000,0x00000000,0x00000802
		DC.L	0x00010004,0x08000208,0x42000000,0x04200802
		DC.L	0x00000000,0x00000008,0x02080100,0x00200800
		DC.L	0x00000404,0x08020208,0x02000000,0x00000002
		DC.L	0x00010404,0x00000200,0x42000000,0x04000000
		DC.L	0x01000000,0x08000000,0x00080100,0x00200800
		DC.L	0x00010000,0x08020200,0x00080000,0x04000000
		DC.L	0x01010404,0x08000000,0x42000100,0x00200800
		DC.L	0x00000004,0x00020008,0x00000100,0x00200000
		DC.L	0x01010000,0x00000208,0x02000000,0x04000802
		DC.L	0x01010400,0x00020000,0x40000000,0x04000802
		DC.L	0x01000000,0x08020200,0x02080000,0x04200002
		DC.L	0x01000000,0x08000200,0x42000100,0x04200002
		DC.L	0x00000400,0x00000000,0x40080100,0x00000002
		DC.L	0x01010004,0x00000200,0x02000100,0x00200002
		DC.L	0x00010000,0x00020008,0x40000000,0x04000000
		DC.L	0x00010400,0x08020208,0x42080000,0x04000800
		DC.L	0x01000004,0x08000200,0x02080100,0x00200000
		DC.L	0x00000400,0x08000008,0x40080100,0x04200800
		DC.L	0x00000004,0x00000200,0x00000100,0x00000802
		DC.L	0x01000404,0x00000000,0x02000000,0x00200802
		DC.L	0x00010404,0x08020008,0x42080000,0x04200800
		DC.L	0x01010404,0x08000208,0x42080100,0x00000802
		DC.L	0x00010004,0x00020000,0x00080100,0x04000002
		DC.L	0x01010000,0x08000000,0x42000000,0x04200802
		DC.L	0x01000404,0x08020208,0x42080100,0x04200000
		DC.L	0x01000004,0x00000008,0x02080000,0x00200800
		DC.L	0x00000404,0x00020208,0x00000000,0x00000000
		DC.L	0x00010404,0x00020200,0x40080000,0x00000002
		DC.L	0x01010400,0x08000008,0x42000000,0x04200802
		DC.L	0x00000404,0x08020000,0x00080100,0x00000000
		DC.L	0x01000400,0x08000208,0x02000100,0x00200802
		DC.L	0x01000400,0x00000208,0x40000100,0x04200000
		DC.L	0x00000000,0x08020000,0x00080000,0x00000800
		DC.L	0x00010004,0x00020208,0x00000000,0x04000002
		DC.L	0x00010400,0x00000008,0x40080000,0x04000800
		DC.L	0x00000000,0x08020008,0x02080100,0x00000800
		DC.L	0x01010004,0x00020200,0x40000100,0x00200002

@SP1:	DC.L	0x80108020,0x00802001,0x20000010,0x10001040
		DC.L	0x80008000,0x00002081,0x20400000,0x00001000
		DC.L	0x00008000,0x00002081,0x00004000,0x00040000
		DC.L	0x00108020,0x00000080,0x20404010,0x10041040
		DC.L	0x00100000,0x00802080,0x20400000,0x10000000
		DC.L	0x00000020,0x00800081,0x00000010,0x10001040
		DC.L	0x80100020,0x00800001,0x20404010,0x00000040
		DC.L	0x80008020,0x00002001,0x00400000,0x10000000
		DC.L	0x80000020,0x00000000,0x20004000,0x00040040
		DC.L	0x80108020,0x00802000,0x00404010,0x10040000
		DC.L	0x80108000,0x00802000,0x00400000,0x10041040
		DC.L	0x80000000,0x00802081,0x20000010,0x00041000
		DC.L	0x80008000,0x00000081,0x00400010,0x10041000
		DC.L	0x00100000,0x00000000,0x20004000,0x00041040
		DC.L	0x00000020,0x00800080,0x20000000,0x00001000
		DC.L	0x80100020,0x00800001,0x00004010,0x00000040
		DC.L	0x00108000,0x00000001,0x00000000,0x10040000
		DC.L	0x00100020,0x00002000,0x00400010,0x10000040
		DC.L	0x80008020,0x00800000,0x20004010,0x10001000
		DC.L	0x00000000,0x00802001,0x00004000,0x00001040
		DC.L	0x80000000,0x00000080,0x00404000,0x00041000
		DC.L	0x00008000,0x00800000,0x20004010,0x00040040
		DC.L	0x00108020,0x00002001,0x00000010,0x10040040
		DC.L	0x80100000,0x00002080,0x20400010,0x10041000
		DC.L	0x00100020,0x00800081,0x20400010,0x00001040
		DC.L	0x80000020,0x00000001,0x00000000,0x00000000
		DC.L	0x00000000,0x00002080,0x00404010,0x00000000
		DC.L	0x00108000,0x00800080,0x20404000,0x10040040
		DC.L	0x00008020,0x00002000,0x00004010,0x10000040
		DC.L	0x80108000,0x00802080,0x00404000,0x10001000
		DC.L	0x80100000,0x00802081,0x20404000,0x00041040
		DC.L	0x00008020,0x00000081,0x20000000,0x00040000
		DC.L	0x00000000,0x00800080,0x20004000,0x00041040
		DC.L	0x00108020,0x00800001,0x00000010,0x00040000
		DC.L	0x80100020,0x00802000,0x20400010,0x10041000
		DC.L	0x00100000,0x00802081,0x00404000,0x00001000
		DC.L	0x80008020,0x00000081,0x20404010,0x00000040
		DC.L	0x80100000,0x00000000,0x00400000,0x10040040
		DC.L	0x80108000,0x00000000,0x00004010,0x00001000
		DC.L	0x00008000,0x00802000,0x20000010,0x00041040
		DC.L	0x80100000,0x00002080,0x00400000,0x10001000
		DC.L	0x80008000,0x00800080,0x20004000,0x00000040
		DC.L	0x00000020,0x00800081,0x20000000,0x10000040
		DC.L	0x80108020,0x00000001,0x00004010,0x10040000
		DC.L	0x00108020,0x00802001,0x20000010,0x10040040
		DC.L	0x00000020,0x00002081,0x20404010,0x10000000
		DC.L	0x00008000,0x00002081,0x00404000,0x00040000
		DC.L	0x80000000,0x00000080,0x20400000,0x10001040
		DC.L	0x00008020,0x00802081,0x00404010,0x00000000
		DC.L	0x80108000,0x00000081,0x20404000,0x10041040
		DC.L	0x00100000,0x00000001,0x00000000,0x00040040
		DC.L	0x80000020,0x00002000,0x20400010,0x10000040
		DC.L	0x00100020,0x00800001,0x00000010,0x10040000
		DC.L	0x80008020,0x00002001,0x00004000,0x10001000
		DC.L	0x80000020,0x00802080,0x20400000,0x10001040
		DC.L	0x00100020,0x00800081,0x00404010,0x00000000
		DC.L	0x00108000,0x00002001,0x00004000,0x10041040
		DC.L	0x00000000,0x00002080,0x00400010,0x00041000
		DC.L	0x80008000,0x00800000,0x20004010,0x00041000
		DC.L	0x00008020,0x00802001,0x00000000,0x00001040
		DC.L	0x80000000,0x00000080,0x20404000,0x00001040
		DC.L	0x80100020,0x00800000,0x20000000,0x00040040
		DC.L	0x80108020,0x00002000,0x00400010,0x10000000
		DC.L	0x00108000,0x00802080,0x20004010,0x10041000

@des1:	move.l	(a2)+,d0
		eor.l	d5,d0
		move.l	d0,d6
		and.l	d2,d0
		move.l	12(a0,d0.w),d4	/* S6 */
		swap	d0
		or.l	4(a0,d0.w),d4	/* S2 */
		ror.l	#8,d6
		and.l	d2,d6
		or.l	8(a0,d6.w),d4	/* S4 */
		swap	d6
		or.l	0(a0,d6.w),d4	/* S0 */
		
		move.l	(a2)+,d0
		eor.l	d5,d0
		move.l	d0,d6
		lsl.l	#4,d0
		and.l	d2,d0
		or.l	12(a1,d0.w),d4	/* S7 */
		swap	d0
		or.l	4(a1,d0.w),d4	/* S3 */
		lsr.l	#4,d6
		and.l	d2,d6
		or.l	8(a1,d6.w),d4	/* S5 */
		swap	d6
		or.l	0(a1,d6.w),d4	/* S1 */
		eor.l	d4,d3
		
		move.l	(a2)+,d0
		eor.l	d3,d0
		move.l	d0,d6
		and.l	d2,d0
		move.l	12(a0,d0.w),d4	/* S6 */
		swap	d0
		or.l	4(a0,d0.w),d4	/* S2 */
		ror.l	#8,d6
		and.l	d2,d6
		or.l	8(a0,d6.w),d4	/* S4 */
		swap	d6
		or.l	0(a0,d6.w),d4	/* S0 */
		
		move.l	(a2)+,d0
		eor.l	d3,d0
		move.l	d0,d6
		lsl.l	#4,d0
		and.l	d2,d0
		or.l	12(a1,d0.w),d4	/* S7 */
		swap	d0
		or.l	4(a1,d0.w),d4	/* S3 */
		lsr.l	#4,d6
		and.l	d2,d6
		or.l	8(a1,d6.w),d4	/* S5 */
		swap	d6
		or.l	0(a1,d6.w),d4	/* S1 */
		eor.l	d4,d5
		dbf		d1,@des1		/* 53 */
		
		ror.l	#1,d5		/* EXSHMSK(R,0x55555555,L,1,tmp) */
		move.l	d5,d2
		eor.l	d3,d2
		andi.l	#0xaaaaaaaa,d2
		eor.l	d2,d3
		eor.l	d2,d5
		ror.l	#1,d3
		move.l	d3,d2		/* EXSHMSK(L,0x00ff00ff,R,8,tmp) */
		lsr.l	#8,d2
		eor.l	d5,d2
		andi.l	#0x00ff00ff,d2
		eor.l	d2,d5
		lsl.l	#8,d2
		eor.l	d2,d3
		move.l	d3,d2		/* EXSHMSK(L,0x33333333,R,2,tmp) */
		lsr.l	#2,d2
		eor.l	d5,d2
		andi.l	#0x33333333,d2
		eor.l	d2,d5
		lsl.l	#2,d2
		eor.l	d2,d3
		swap	d5			/* EXSHMSK(R,0x0000ffff,L,16,tmp) */
		move.w	d5,d2
		move.w	d3,d5
		move.w	d2,d3
		swap	d5
		move.l	d5,d2		/* EXSHMSK(R,0x0f0f0f0f,L,4,tmp) */
		lsr.l	#4,d2
		eor.l	d3,d2
		andi.l	#0x0f0f0f0f,d2
		eor.l	d2,d3
		lsl.l	#4,d2
		eor.l	d2,d5
		
		movea.l	block,a0
		move.l	d5,(a0)+
		move.l	d3,(a0)
		movem.l	(a7)+,a2/d3-d6	
		}			/* end asm	*/
return;
}

/******* end ******/

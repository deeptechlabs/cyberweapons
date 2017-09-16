#ifndef _MD2_DEFINED

#define _MD2_DEFINED

/* The MD2 block size and message digest sizes, in bytes */

#define MD2_DATASIZE	16
#define MD2_DIGESTSIZE	16

/* The structure for storing MD2 info */

typedef struct {
			   BYTE state[ MD2_DATASIZE ];	/* MD2 current state/digest */
			   BYTE checksum[ MD2_DIGESTSIZE ];	/* Message checksum */
			   BYTE data[ MD2_DATASIZE ];	/* MD2 data buffer */
			   int length;					/* Length of data in block */
			   BOOLEAN done;				/* Whether final digest present */
			   } MD2_INFO;

/* Message digest functions */

void md2Initial( MD2_INFO *md2Info );
void md2Update( MD2_INFO *md2Info, BYTE *buffer, int count );
void md2Final( MD2_INFO *md2Info );

#endif /* _MD2_DEFINED */


/*  higher level structures to manipulate elliptic curve public keys  */

#define MAX_NAME_SIZE	64
#define MAX_PHRASE_SIZE	256

/*  64 bit key for 148 bit field, 128 bit key for 226 bit fields.
	In units of ELEMENTS.  Used in symmetric cipher.
*/
#define KEY_LENGTH	2

typedef struct {
	POINT	p;
	POINT	q;
	CURVE	crv;
	char	name[MAX_NAME_SIZE];
	char	address[MAX_NAME_SIZE];
}  PUBKEY;
}  PUBKEY;

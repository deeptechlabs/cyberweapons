/*
 *	Encrypt a Message with New Crypt Algorithm
 *	D.P.Mitchell  83/06/08.
 */

#include <stdio.h>
#include "crypt.h"

main(argc, argv)
int argc;
char *argv[];
{
	Block key;
	Block plaintext;
	Block ciphertext;
	extern Block setup();

	key = setup(argc, argv);
	key_setup(&key, 0);
	ciphertext.left = 0;
	ciphertext.right = 0;
	while (p_source(&plaintext)) {
		plaintext.left ^= ciphertext.left;
		plaintext.right ^= ciphertext.right;
		des(&plaintext);
		ciphertext = plaintext;
		c_sink(&ciphertext);
	}
}

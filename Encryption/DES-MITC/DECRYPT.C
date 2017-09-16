/*
 *	Decrypt a Message with New Crypt Algorithm
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
	Block lastcipher;
	extern Block setup();

	key = setup(argc, argv);
	key_setup(&key, 1);
	lastcipher.left = 0;
	lastcipher.right = 0;
	while (c_source(&ciphertext)) {
		plaintext = ciphertext;
		des(&plaintext);
		plaintext.left ^= lastcipher.left;
		plaintext.right ^= lastcipher.right;
		lastcipher = ciphertext;
		p_sink(&plaintext);
	}
}

/*

FILENAME:  main.c

AES Submission: FROG

Principal Submitter: TecApro

*/

#include "frog.h"
#include "tests.h"

main () {
	VariableKeyKAT ("ecb_vk.txt");
	VariableTextKAT ("ecb_vt.txt");

	MonteCarloTestECB ("ecb_e_m.txt", DIR_ENCRYPT);
	MonteCarloTestECB ("ecb_d_m.txt", DIR_DECRYPT);

	MonteCarloTestCBCEncrypt ("cbc_e_m.txt");
	MonteCarloTestCBCDecrypt ("cbc_d_m.txt");
	return 0;
}
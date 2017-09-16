#include <stdio.h>
#include <unistd.h>
#include "client.h"
#include "des.h"

/* Change the pass phrase on a wallet */

int lucre_passwd(EC_W_Wallet wallet)
{
    EC_Errno		err;
    char		pwbuf[1000];
    char		walletpp[1000];
    int			res;
    int			ret = -1;

    if (!wallet) return -1;

    /* Try to get a password */
    if (!wallet->userprivkey) {
	/* Try no password */
	EC_W_wallet_usephrase(wallet, "");
	if (!wallet->userprivkey) {
	    printf("Enter wallet pass phrase to unlock your private key.\n");
	    fflush(stdout);
	    res = des_read_pw_string(pwbuf, sizeof(pwbuf) - 1,
					"Pass phrase: ", 0);
	    CHECK(read_pw_string, res);
	    err = EC_W_wallet_usephrase(wallet, pwbuf);
	    if (err) {
		printf("Bad password.  Aborting.\n");
		return -1;
	    }
	}
    }

    /* Get a new one */
    printf("\nEnter a new pass phrase to be used to protect "
	    "your signature key.\n");
    res = des_read_pw_string(pwbuf, sizeof(pwbuf)-1, "pass phrase: ", 1);
    if (res) {
	printf("Passwords don't match.  Aborting.\n");
	return -1;
    }
    strcpy(walletpp, pwbuf);

    /* Set the new pass phrase */
    err = EC_W_wallet_setphrase(wallet, walletpp);
    CHECK(wallet_setphrase, err);
    ret = 0;

clean:
    return ret;
}

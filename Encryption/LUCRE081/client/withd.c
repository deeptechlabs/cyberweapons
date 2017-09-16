#include <stdio.h>
#include <unistd.h>
#include "client.h"
#include "des.h"

/* Make a withdrawal from a wallet */

int lucre_withdraw(EC_W_Wallet wallet, UInt32 amount, UInt32 minpayments)
{
    EC_M_Msg		msg = NULL;
    EC_M_Bank_mkey	bank_mkey = NULL;
    EC_Errno		err;
    char		pwbuf[1000];
    int			res;
    int			sockfd = -1;
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

    /* Get the bank's keys and addresses */
    bank_mkey = EC_W_bankkeys_lookup(wallet, wallet->userrec->bankID, 0);
    CHECK(bankkeys_lookup, !bank_mkey);

    /* Connect to the bank */
    sockfd = bank_socket(bank_mkey);
    CHECK(bank_socket, sockfd < 0);

    /* Do the withdrawal protocol */
    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);
    err = EC_W_withdraw_1(wallet, msg, amount, minpayments);
    CHECK(withdraw_1, err);
    err = EC_M_BTE_encode(msg, NULL, &sockfd);
    CHECK(encode, err);
    EC_M_clear_msg(msg);
    err = EC_M_BTE_decode(msg, NULL, &sockfd);
    CHECK(decode, err);
    err = EC_W_withdraw_2(wallet, msg, &amount);
    CHECK(withdraw_2, err);
    printf("Received %d from mint\n", amount);
    ret = 0;

clean:
    EC_M_free_msg(msg);
    EC_M_free_bank_mkey(bank_mkey);
    close(sockfd);

    return ret;
}

#include "client.h"

/* Check the balance of an account */
int lucre_balance(EC_W_Wallet wallet)
{
    EC_M_Status		status = NULL;
    int			ret = -1;

    /* Get the status */
    status = EC_W_status_read(wallet);
    CHECK(status_read, !status);

    printf("Account balance for %s:\n", wallet->userrec->username);
    printf("At the bank: %d\n", status->balance);
    printf("In the wallet: %d\n", status->cash);
    printf("\nNote: These amounts may not be accurate unless you just did a "
	    "withdrawal.\n      Doing a withdrawal of 0 is useful to sync "
	    "these numbers.\n");
    ret = 0;

clean:
    EC_M_free_status(status);
    return ret;
}

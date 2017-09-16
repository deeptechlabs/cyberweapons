#include <stdio.h>
#include <unistd.h>
#include "client.h"
#include "des.h"

/* Make a cash deposit from a wallet */

int lucre_deposit_cash(EC_W_Wallet wallet, UInt32 amount)
{
    EC_M_Msg		msg = NULL;
    EC_M_Bank_mkey	bank_mkey = NULL;
    EC_M_Payment	payment = NULL;
    EC_Errno		err;
    int			seqno;
    int			sockfd = -1;
    int			ret = -1;

    if (!wallet) return -1;

    /* Get the bank's keys and addresses */
    bank_mkey = EC_W_bankkeys_lookup(wallet, wallet->userrec->bankID, 0);
    CHECK(bankkeys_lookup, !bank_mkey);

    /* Connect to the bank */
    sockfd = bank_socket(bank_mkey);
    CHECK(bank_socket, sockfd < 0);

    /* Do the deposit protocol */
    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);
    err = EC_W_create_payment(wallet, amount, EC_M_CURRENCY_US_CENTS,
				wallet->userrec->username,
				wallet->userrec->bankID, "", &seqno);
    CHECK(create_payment, err);
    err = EC_W_make_payment(wallet, msg, seqno);
    CHECK(make_payment, err);
    err = EC_M_decompile_payment(&payment, msg);
    CHECK(decompile_payment, err);
    EC_M_clear_msg(msg);
    ret = lucre_deposit_payment(wallet, msg, &payment, sockfd);

clean:
    EC_M_free_msg(msg);
    EC_M_free_bank_mkey(bank_mkey);
    EC_M_free_payment(payment);
    close(sockfd);

    return ret;
}

int lucre_deposit_payment(EC_W_Wallet wallet, EC_M_Msg msg,
    EC_M_Payment *payment, int sockfd)
{
    int			ret = -1;
    int			seqno;
    int			accepted, amount;
    EC_Errno		err;
    EC_M_Dep_ack	dep_ack = NULL;
    int			i;
    int			numdeps;

    /* First check for uncompleted payments */
    EC_M_clear_msg(msg);
    err = EC_W_deposit_all_payments_1(wallet, msg, &numdeps);
    CHECK(deposit_all_payments_1, err);
    if (numdeps) {
	err = EC_M_BTE_encode(msg, NULL, &sockfd);
	CHECK(encode, err);
	EC_M_clear_msg(msg);
	err = EC_M_BTE_decode(msg, NULL, &sockfd);
	CHECK(decode, err);
	err = EC_W_deposit_all_payments_2(wallet, msg, &dep_ack);
	CHECK(deposit_all_payments_2, err);
	if (dep_ack) for(i=0;i<dep_ack->numacks;++i) {
	    printf("Deposit #%d: ", dep_ack->dep_1ack[i]->seqno);
	    if (dep_ack->dep_1ack[i]->result == 3) {
		printf("%d accepted\n", dep_ack->dep_1ack[i]->amount);
	    } else {
		printf("rejected (reason = %d)\n",
			dep_ack->dep_1ack[i]->amount);
	    }
	}
	EC_M_free_dep_ack(dep_ack);
	dep_ack = NULL;
    }

    /* Now do the payment */
    err = EC_W_recdb_put(wallet, *payment, &seqno);
    CHECK(recdb_put, err);
    *payment = NULL;
    err = EC_W_deposit_payment_1(wallet, msg, seqno);
    CHECK(deposit_payment_1, err);
    err = EC_M_BTE_encode(msg, NULL, &sockfd);
    CHECK(encode, err);
    EC_M_clear_msg(msg);
    err = EC_M_BTE_decode(msg, NULL, &sockfd);
    CHECK(decode, err);
    err = EC_W_deposit_payment_2(wallet, msg, seqno, &accepted, &amount);
    CHECK(deposit_payment_2, err);

    printf("Deposit #%d: ", seqno);
    if (accepted) {
	printf("%d accepted\n", amount);
    } else {
	printf("rejected (reason = %d)\n", amount);
    }
    ret = 0;

clean:
    EC_M_free_dep_ack(dep_ack);
    return ret;
}

#include <stdio.h>
#include <unistd.h>
#include "client.h"

/* This is the master public key used to sign SETUP messages */
static const char mastern[] =
"ccff1d2c099b7214f36a1a48214a6fc8427ee2d6c583a4a2e2e6a48b10c94133"
"77c1ffabdf7371123924a3ad1f097b816b87121c447e8251ead83c223b548cb2"
"2d87767f2e04a7b6f82cc6c26507e4614344a62c4148b3b6d64eccd9ebf4eb9d";

static const char mastere[] = "11";

static void callback(int stage, int attempt)
{
     printf("%c", ",.;:"[stage]);
     fflush(stdout);
}

/* Open an account with the bank and create the wallet for it */
int lucre_openacc(char *walletid, char *walletpp, char *accID, char *accpw)
{
    EC_W_Wallet		wallet = NULL;
    EC_M_Msg		msg = NULL;
    EC_Errno		err;

    EC_M_Currency	currency = EC_M_CURRENCY_US_CENTS;
    BIGNUM *		setup_n = EC_U_str2bn(mastern, strlen(mastern));
    BIGNUM *		setup_e = EC_U_str2bn(mastere, strlen(mastere));
    int			sockfd = -1;
    int			ret = -1;

    CHECK(setup, !setup_n || !setup_e);

    /* Connect to the bank */
    sockfd = make_socket("199.217.176.1", 5885);
    CHECK(make_socket, sockfd < 0);

    /* Do the openacc protocol */
    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);
    err = EC_W_wallet_create_1(&wallet, msg, walletid, walletpp, callback);
    puts("");
    CHECK(wallet_create_1, err);
    err = EC_M_BTE_encode(msg, NULL, &sockfd);
    CHECK(encode, err);
    EC_M_clear_msg(msg);
    err = EC_M_BTE_decode(msg, NULL, &sockfd);
    CHECK(decode, err);
    err = EC_W_wallet_create_2(&wallet, msg, accID, currency, accpw, setup_n,
				setup_e);
    CHECK(wallet_create_2, err);
    err = EC_M_BTE_encode(msg, NULL, &sockfd);
    CHECK(encode, err);
    EC_M_clear_msg(msg);
    err = EC_M_BTE_decode(msg, NULL, &sockfd);
    CHECK(decode, err);
    err = EC_W_wallet_create_3(&wallet, msg);
    CHECK(wallet_create_3, err);
    ret = 0;

clean:
    close(sockfd);
    EC_W_wallet_close(wallet);
    EC_M_free_msg(msg);
    return ret;
}

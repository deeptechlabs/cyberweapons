#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include "client.h"

/* Get a payment from the file descriptor payfd.  If armor == 1, it is
   ASCII-armored. */
int lucre_getpay_fd(EC_W_Wallet wallet, int payfd, int armor)
{
    EC_Errno		err;
    EC_M_Msg		msg = NULL;
    int			ret = -1;
    EC_M_Payment	payment = NULL;
    EC_M_Bank_mkey	bank_mkey = NULL;
    int			sockfd = -1;

    if (!wallet) return -1;

    /* Get the bank's keys and addresses */
    bank_mkey = EC_W_bankkeys_lookup(wallet, wallet->userrec->bankID, 0);
    CHECK(bankkeys_lookup, !bank_mkey);

    /* Connect to the bank */
    sockfd = bank_socket(bank_mkey);
    CHECK(bank_socket, sockfd < 0);

    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);
    if (!armor) {
	err = EC_M_BTE_decode(msg, NULL, &payfd);
	CHECK(decode, err);
    } else {
	err = EC_M_ATE_decode(msg, NULL, &payfd);
	CHECK(decode, err);
    }
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

int lucre_getpay(EC_W_Wallet wallet)
{
    int                 payfd = -1;
    int			spayfd = -1;
    char                inbuf[1000];
    char                portstr[1000];
    unsigned short      port;
    int                 ret = -1;
    int                 tcp;
    struct sockaddr	addr;
    int			addrlen;

    /* Ask where to get the payment from */
    printf("Get payment from a (f)ile, or the (n)etwork (f/n): ");
    fflush(stdout);
    fgets(inbuf, sizeof(inbuf)-1, stdin);
    strcpy_strip(portstr, inbuf);
    switch(portstr[0]) {
    case 'f':
        printf("Enter filename: ");
        fflush(stdout);
        fgets(inbuf, sizeof(inbuf)-1, stdin);
        strcpy_strip(portstr, inbuf);
        payfd = open(portstr, O_RDONLY);
        CHECK(open, payfd < 0);
        tcp = 0;
        break;

    case 'n':
        printf("Enter port number to listen on [5654]: ");
        fflush(stdout);
        fgets(inbuf, sizeof(inbuf)-1, stdin);
        strcpy_strip(portstr, inbuf);
        port = atoi(portstr);
        if (!port) port = 5654;
        spayfd = make_listen(port);
        CHECK(make_listen, spayfd < 0);
        payfd = accept(spayfd, &addr, &addrlen);
        CHECK(accept, payfd < 0);
        close(spayfd);
        spayfd = -1;
        tcp = 1;
        break;

    default:
        printf("Unexpected response.  Aborting.\n");
        return -1;
    }

    ret = lucre_getpay_fd(wallet, payfd, !tcp);

clean:
    close(payfd);
    close(spayfd);
    return ret;
}

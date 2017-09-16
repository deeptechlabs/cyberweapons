#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include "client.h"

/* Expect a payment request */

int lucre_expreq(EC_W_Wallet wallet)
{
    int			payfd = -1;
    int			spayfd = -1;
    char		inbuf[1000];
    char		portstr[1000];
    unsigned short	port;
    int			ret = -1;
    int			tcp;
    struct sockaddr	addr;
    int			addrlen;
    EC_M_Msg		msg = NULL;
    EC_M_Payreq		payreq = NULL;
    int			seqno;
    EC_Errno		err;

    /* Ask where to get the request from */
    printf("Get payment request from a (f)ile, or the (n)etwork (f/n): ");
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

    /* Get the request */
    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);

    if (tcp) {
	err = EC_M_BTE_decode(msg, NULL, &payfd);
	CHECK(decode, err);
    } else {
	err = EC_M_ATE_decode(msg, NULL, &payfd);
	CHECK(decode, err);
    }
    err = EC_M_decompile_payreq(&payreq, msg);
    CHECK(decompile_payreq, err);
    EC_M_clear_msg(msg);

    /* Check with the user */
    printf("Payment request received:\n");
    if (payreq->currency != wallet->userrec->currency) {
	printf("Unknown currency; cannot make payment.\n");
	goto clean;
    }
    printf("Amount: %d\nShop: %s\nDescription: %s\n", payreq->amount,
	    payreq->shop_accID, payreq->descr);

    printf("OK to pay this (y/N)? ");
    fflush(stdout);
    fgets(inbuf, sizeof(inbuf)-1, stdin);
    strcpy_strip(portstr, inbuf);
    if (portstr[0] != 'y' && portstr[0] != 'Y') {
	printf("Ignoring payment request.\n");
	goto clean;
    }

    /* Send a payment */
    if (payreq->conn_host && *(payreq->conn_host) && payreq->conn_port) {
	/* They told us where to send it */
	close(payfd);
	payfd = make_socket(payreq->conn_host, payreq->conn_port);
	CHECK(make_socket, payfd);
	tcp = 1;
    } else if (!tcp) {
	/* Get a filename */
        printf("Enter filename to store payment: ");
        fflush(stdout);
        fgets(inbuf, sizeof(inbuf)-1, stdin);
        strcpy_strip(portstr, inbuf);
        payfd = open(portstr, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
        CHECK(open, payfd < 0);
    }

    err = EC_W_create_payment(wallet, payreq->amount, payreq->currency,
				payreq->shop_accID, payreq->shop_bankID,
				payreq->descr, &seqno);
    CHECK(create_payment, err);
    err = EC_W_make_payment(wallet, msg, seqno);
    CHECK(make_payment, err);
    if (tcp) {
        err = EC_M_BTE_encode(msg, NULL, &payfd);
        CHECK(encode, err);
    } else {
        err = EC_M_ATE_encode(msg, "PAYMENT", NULL, NULL, &payfd);
        CHECK(encode, err);
    }
    ret = 0;

clean:
    EC_M_free_msg(msg);
    EC_M_free_payreq(payreq);
    close(payfd);
    close(spayfd);
    return ret;
}

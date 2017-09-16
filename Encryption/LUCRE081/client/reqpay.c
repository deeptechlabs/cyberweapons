#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "client.h"

/* Make a payment request */

int lucre_reqpay(EC_W_Wallet wallet, int amount, char *descr)
{
    EC_M_Msg		msg = NULL;
    char		inbuf[1000];
    char		dest[1000];
    int			payfd = -1;
    char		portstr[1000];
    unsigned short	port;
    EC_Errno		err;
    int			tcp;
    int			ret = -1;

    /* Find out how this should be dispatched */
    printf("Write to a (f)ile, or send by (n)etwork (f/n): ");
    fflush(stdout);
    fgets(inbuf, sizeof(inbuf)-1, stdin);
    strcpy_strip(dest, inbuf);
    switch(dest[0]) {
    case 'f':
        printf("Enter filename: ");
        fflush(stdout);
        fgets(inbuf, sizeof(inbuf)-1, stdin);
        strcpy_strip(dest, inbuf);
        payfd = open(dest, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
        CHECK(open, payfd < 0);
        tcp = 0;
        break;

    case 'n':
        printf("Enter hostname: ");
        fflush(stdout);
        fgets(inbuf, sizeof(inbuf)-1, stdin);
        strcpy_strip(dest, inbuf);
        printf("Enter port number [5654]: ");
        fflush(stdout);
        fgets(inbuf, sizeof(inbuf)-1, stdin);
        strcpy_strip(portstr, inbuf);
        port = atoi(portstr);
        if (!port) port = 5654;
        payfd = make_socket(dest, port);
        CHECK(make_socket, payfd < 0);
        tcp = 1;
        break;

    default:
        printf("Unexpected response.  Aborting.\n");
        return -1;
    }

    /* Create the payment request */
    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);

    err = EC_W_request_payment(msg, wallet->userrec->currency, amount,
	wallet->userrec->bankID, wallet->userrec->username, descr, "", 0);
    CHECK(request_payment, err);
    if (tcp) {
	/* Send the request, wait for a response */
	err = EC_M_BTE_encode(msg, NULL, &payfd);
	CHECK(encode, err);
	ret = lucre_getpay_fd(wallet, payfd, 0);
    } else {
	/* Just write the payment */
	err = EC_M_ATE_encode(msg, "PAYMENT REQUEST", NULL, NULL,
				&payfd);
	CHECK(encode, err);
	ret = 0;
    }

clean:
    close(payfd);
    EC_M_free_msg(msg);
    
    return ret;
}

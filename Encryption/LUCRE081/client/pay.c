#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "client.h"

/* Make a payment */
int lucre_pay(EC_W_Wallet wallet, int amount, char *shop, char *descr)
{
    EC_M_Msg		msg = NULL;
    EC_Errno		err;
    UInt32		seqno = 0;
    int			payfd = -1;
    char		inbuf[1000];
    char		dest[1000];
    char		portstr[1000];
    unsigned short	port;
    int			ret = -1;
    int			tcp;

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

    msg = EC_M_new_msg();
    CHECK(new_msg, !msg);
    err = EC_W_create_payment(wallet, amount, wallet->userrec->currency, shop,
				wallet->userrec->bankID, descr, &seqno);
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
    close(payfd);
    EC_M_free_msg(msg);

    return ret;
}

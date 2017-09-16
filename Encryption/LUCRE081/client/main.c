#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include "client.h"
#include "des.h"

/* Make a socket connection to a specified addr and port */
int make_socket(char *host, unsigned short port)
{
    struct protoent *proto;
    int tcpproto;
    struct sockaddr_in addr;
    struct hostent *hostent;
    int ev;
    int sock;

    proto = getprotobyname("tcp");
    if (proto) {
	tcpproto = proto->p_proto;
    } else {
	tcpproto = 6;
    }
    sock = socket(AF_INET, SOCK_STREAM, tcpproto);
    if (sock < 0) {
	return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    /* Is this a number or a name? */
    if (host[0] >= '0' && host[0] <= '9') {
	addr.sin_addr.s_addr = inet_addr(host);
    } else {
	hostent = gethostbyname(host);
	if (!hostent) {
	    close(sock);
	    return -1;
	}
	addr.sin_addr.s_addr = **(unsigned long **)&(hostent->h_addr);
    }

    ev = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ev < 0) {
	close(sock);
	return -1;
    }
    return sock;
}

int make_listen(unsigned short port)
{
    struct protoent *proto;
    int tcpproto;
    struct sockaddr_in addr;
    int ev;
    int sock;

    proto = getprotobyname("tcp");
    if (proto) {
	tcpproto = proto->p_proto;
    } else {
	tcpproto = 6;
    }
    sock = socket(AF_INET, SOCK_STREAM, tcpproto);
    if (sock < 0) {
	return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    ev = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ev < 0) {
	close(sock);
	return -1;
    }
    listen(sock, 5);

    return sock;
}

/* Try each of the listed addresses in an attempt to connect to the bank */
int bank_socket(EC_M_Bank_mkey bank_mkey)
{
    int		i;
    int		sockfd;

    if (!bank_mkey) return -1;

    for (i=0;i<bank_mkey->numaddrs;++i) {
	sockfd = make_socket(bank_mkey->bankaddr[i], bank_mkey->bankport);
	if (sockfd >= 0) return sockfd;
    }

    return -1;
}

/* Copy src to dest, stripping leading and trailing writespace */
void strcpy_strip(char *dest, char *src)
{
    char *		end;
    int			len = 0;

    while(*src && isspace(*src)) ++src;
    end = strchr(src, '\0');
    if(!end) return;
    if (end != src) {
	--end;
	while(end > src && isspace(*end)) --end;
	len = end - src + 1;
    }

    memmove(dest, src, len);

    dest[len] = 0;
}

int main(int argc, char **argv)
{
    char *		progname = argv[0];
    EC_Errno		err;
    int			done;
    EC_W_Wallet		wallet = NULL;
    char *		walletid = NULL;
    char		cmdbuf[1000];
    char *		cmdptr;
    int			res;
    int			amount;
    int			minpayments;
    char		shop[1000];
    char		descr[1000];
    int			openaccount = 0;

    /* Check the arguments */
    --argc; ++argv;
    while (argc) {
	if (!strcmp(argv[0], "-o")) {
	    /* Open an account */
	    openaccount = 1;
	    --argc; ++argv;
	} else if (!strcmp(argv[0], "-w") && argc > 1) {
	    walletid = argv[1];
	    --argc; ++argv;
	    --argc; ++argv;
	} else {
	    /* Error */
	    fprintf(stderr, "Usage: %s [-w walletid] [-o]\n", progname);
	    exit(1);
	}
    }

    err = EC_main_init(NULL, NULL, NULL, NULL, NULL);
    if (err) {
	fprintf(stderr, "Error initializing ecash!\n");
	exit(1);
    }

    printf("Sample -lucre client, version 0.1\n");
    printf("Using library version: %s\n", EC_main_get_libver());

    if (openaccount) {
	char		accID[1000];
	char		accpw[1000];
	char		walletpp[1000];
	char		resp[1000];
	char *		walletname;
	struct stat	st;

	/* See if the wallet exists yet */
	walletname = EC_W_wallet_getname(walletid);
	if (!walletname) {
	    fprintf(stderr, "Cannot determine wallet name!\n");
	    exit(1);
	}
	res = stat(walletname, &st);
	if (!res) {
	    /* There's already something there! */
	    printf("\nA wallet already exists at the pathname\n%s\n",
		    walletname);
	    free(walletname);
	    printf("It is unlikely you want to overwrite this wallet.\n");
	    printf("Do you really want to do so (y/N)? ");
	    fflush(stdout);
	    if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) exit(1);
	    strcpy_strip(resp, cmdbuf);
	    if (resp[0] != 'y' && resp[0] != 'Y') {
		printf("Account opening aborted.\n");
		exit(1);
	    }
	}

	/* Get the accountID, account password, and wallet pass phrase */
	printf("\nEnter account name for new account: ");
	fflush(stdout);
	if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) exit(1);
	strcpy_strip(accID, cmdbuf);
	printf("Enter password for new account: ");
	fflush(stdout);
	if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) exit(1);
	strcpy_strip(accpw, cmdbuf);
	printf("\nYou should now enter a pass phrase to be used to protect "
		"your signature key.\n");
	res = des_read_pw_string(cmdbuf, sizeof(cmdbuf)-1, "pass phrase: ", 1);
	if (res) {
	    printf("Passwords don't match.  Aborting.\n");
	    exit(1);
	}
	strcpy(walletpp, cmdbuf);

	/* Open the account */
	res = lucre_openacc(walletid, walletpp, accID, accpw);
	printf("Account opening %s.\n", res ? "failed" : "succeeded");
	if (res) {
	    exit(1);
	}
    }

    /* Try to open the wallet */
    wallet = EC_W_wallet_open(walletid);
    if (!wallet) {
	fprintf(stderr, "Cannot open wallet!  Set $ECWALLET to the location "
		"of your wallet, or use\n   %s -w walletid\n", progname);
	exit(1);
    }

    done = 0;
    while(!done) {
	/* Get a command */
	printf("\ns-lc) ");
	fflush(stdout);
	if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) break;

	/* Parse it */
	cmdptr = cmdbuf;
	while (*cmdptr == ' ' || *cmdptr == '\t') ++cmdptr;
	switch(*cmdptr) {
	case '\n':
	    /* blank line */
	    break;

	case 'w':
	    /* withdraw */
	    while (*cmdptr != ' ' && *cmdptr != '\t') ++cmdptr;
	    amount = 0;
	    minpayments = 8;
	    sscanf(cmdptr, "%d %d", &amount, &minpayments);
	    res = lucre_withdraw(wallet, amount, minpayments);
	    printf("Withdrawal %s.\n", res ? "failed" : "succeeded");
	    break;

	case 'd':
	    /* deposit */
	    while (*cmdptr != ' ' && *cmdptr != '\t') ++cmdptr;
	    amount = 0;
	    sscanf(cmdptr, "%d", &amount);
	    res = lucre_deposit_cash(wallet, amount);
	    printf("Deposit %s.\n", res ? "failed" : "succeeded");
	    break;

	case 'p':
	    /* pay */
	    while (*cmdptr != ' ' && *cmdptr != '\t') ++cmdptr;
	    amount = 0;
	    sscanf(cmdptr, "%d", &amount);
	    printf("Paying %d:\n", amount);
	    printf("Enter name of shop [@]: ");
	    fflush(stdout);
	    if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) break;
	    strcpy_strip(shop, cmdbuf);
	    if (shop[0] == '\0') {
		strcpy(shop, "@");
	    }
	    printf("Enter description: ");
	    fflush(stdout);
	    if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) break;
	    strcpy_strip(descr, cmdbuf);
	    res = lucre_pay(wallet, amount, shop, descr);
	    printf("Payment %s.\n", res ? "failed" : "succeeded");
	    break;

	case 'g':
	    /* get payment */
	    res = lucre_getpay(wallet);
	    printf("Get payment %s.\n", res ? "failed" : "succeeded");
	    break;

	case 'r':
	    /* request payment */
	    while (*cmdptr != ' ' && *cmdptr != '\t') ++cmdptr;
	    amount = 0;
	    sscanf(cmdptr, "%d", &amount);
	    printf("Payment request for %d:\n", amount);
	    printf("Enter description: ");
	    fflush(stdout);
	    if (!fgets(cmdbuf, sizeof(cmdbuf)-1, stdin)) break;
	    strcpy_strip(descr, cmdbuf);
	    res = lucre_reqpay(wallet, amount, descr);
	    printf("Payment request %s.\n", res ? "failed" : "succeeded");
	    break;

	case 'e':
	    /* expect request */
	    res = lucre_expreq(wallet);
	    printf("Payment request receipt %s.\n", res ? "failed" :
		    "succeeded");
	    break;

	case 'b':
	    /* balance */
	    res = lucre_balance(wallet);
	    break;

	case 'c':
	    /* change passphrase */
	    res = lucre_passwd(wallet);
	    printf("Pass phrase change %s.\n", res ? "failed" : "succeeded");
	    break;

	case 'q':
	    /* quit */
	    done = 1;
	    break;

	default:
	    printf("\nValid commands are:\n");
	    printf("withdraw [amount [minpayments]]\n");
	    printf("deposit [amount]\n");
	    printf("pay [amount]\n");
	    printf("get_pay\n");
	    printf("request_payment [amount]\n");
	    printf("expect_request\n");
	    printf("balance_check\n");
	    printf("change_passphrase\n");
	    printf("quit\n");
	    printf("\nCommands may be abbreviated to their first letter.\n");
	    printf("Unsupplied arguments default as follows:\n");
	    printf("    amount = 0\n    minpayments = 8\n");
	    printf("\nAll amounts are in US _cents_, not dollars.\n");
	    printf("'pay 5' means pay 5 cents; 'withdraw 200' means "
		    "withdraw 2 dollars.\n");
	    break;
	}
    }

    EC_W_wallet_close(wallet);
    EC_main_cleanup();

    printf("\n");
    return 0;
}

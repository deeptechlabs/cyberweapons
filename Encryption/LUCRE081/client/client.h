#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "lucre.h"

#define CHECK(fcn,tst) do { if (tst) { puts("Error in "#fcn); goto clean; } } while(0)

int make_socket(char *host, unsigned short port);
int bank_socket(EC_M_Bank_mkey bank_mkey);
int make_listen(unsigned short port);
void strcpy_strip(char *dest, char *src);
int lucre_openacc(char *walletid, char *walletpp, char *accID, char *accpw);
int lucre_withdraw(EC_W_Wallet wallet, UInt32 amount, UInt32 minpayments);
int lucre_deposit_cash(EC_W_Wallet wallet, UInt32 amount);
int lucre_deposit_payment(EC_W_Wallet wallet, EC_M_Msg msg,
    EC_M_Payment *payment, int sockfd);
int lucre_pay(EC_W_Wallet wallet, int amount, char *shop, char *descr);
int lucre_getpay_fd(EC_W_Wallet wallet, int payfd, int armor);
int lucre_getpay(EC_W_Wallet wallet);
int lucre_reqpay(EC_W_Wallet wallet, int amount, char *descr);
int lucre_expreq(EC_W_Wallet wallet);
int lucre_balance(EC_W_Wallet wallet);
int lucre_passwd(EC_W_Wallet wallet);

#endif

#include "lucre.h"

/*
   payreq =
     [
        int	currency
        int	amount
        time	timestamp
        int	shop_bankID
        string  shop_accID
        string  descr
        string  conn_host
        int     conn_port
     ]
 */

EC_M_Payreq EC_M_new_payreq(EC_M_Currency currency, UInt32 amount,
    time_t timestamp, UInt32 shop_bankID, char *shop_accID, char *descr,
    char *conn_host, UInt32 conn_port)
{
    EC_M_Payreq newpayreq;

    if (!shop_accID || !descr || !conn_host) return NULL;
    newpayreq = (EC_M_Payreq) EC_G_malloc(sizeof(struct EC_M_Payreq_s));
    if (!newpayreq) return newpayreq;

    newpayreq->currency = currency;
    newpayreq->amount = amount;
    newpayreq->timestamp = timestamp;
    newpayreq->shop_bankID = shop_bankID;
    newpayreq->shop_accID = shop_accID;
    newpayreq->descr = descr;
    newpayreq->conn_host = conn_host;
    newpayreq->conn_port = conn_port;
    return newpayreq;
}

EC_M_Payreq EC_M_clone_payreq(EC_M_Payreq payreq)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Currency currency;
    UInt32 amount;
    time_t timestamp;
    UInt32 shop_bankID;
    EC_M_Payreq newpayreq;
    char *shop_accID = NULL;
    char *descr = NULL;
    char *conn_host = NULL;
    UInt32 conn_port;
    
    err = EC_M_examine_payreq(payreq, &currency, &amount, &timestamp,
	&shop_bankID, &shop_accID, &descr, &conn_host, &conn_port);
    if (!err) {
	newpayreq = EC_M_new_payreq(currency, amount, timestamp, shop_bankID,
	    shop_accID, descr, conn_host, conn_port);
	if (newpayreq) return newpayreq;
    }

    if (shop_accID) EC_G_free(shop_accID);
    if (descr) EC_G_free(descr);
    if (conn_host) EC_G_free(conn_host);
    return NULL;
}

EC_Errno EC_M_examine_payreq(EC_M_Payreq payreq, EC_M_Currency *currency,
    UInt32 *amount, time_t *timestamp, UInt32 *shop_bankID, char **shop_accID,
    char **descr, char **conn_host, UInt32 *conn_port)
{ 
    EC_M_Currency mycurrency;
    UInt32 myamount;
    time_t mytimestamp;
    UInt32 myshop_bankID;
    char *myshop_accID;
    char *mydescr;
    char *myconn_host;
    UInt32 myconn_port;

    if (!payreq) return EC_ERR_INTERNAL;

    mycurrency = payreq->currency;
    myamount = payreq->amount;
    mytimestamp = payreq->timestamp;
    myshop_bankID = payreq->shop_bankID;
    myshop_accID = EC_G_strdup(payreq->shop_accID);
    mydescr = EC_G_strdup(payreq->descr);
    myconn_host = EC_G_strdup(payreq->conn_host);
    myconn_port = payreq->conn_port;

    if (!myshop_accID || !mydescr || !myconn_host) {
	/* Didn't copy properly; abort */
	if (myshop_accID) EC_G_free(myshop_accID);
	if (mydescr) EC_G_free(mydescr);
	if (myconn_host) EC_G_free(myconn_host);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (currency) *currency = mycurrency;
    if (amount) *amount = myamount;
    if (timestamp) *timestamp = mytimestamp;
    if (shop_bankID) *shop_bankID = myshop_bankID;
    if (shop_accID) *shop_accID = myshop_accID; else EC_G_free(myshop_accID);
    if (descr) *descr = mydescr; else EC_G_free(mydescr);
    if (conn_host) *conn_host = myconn_host; else EC_G_free(myconn_host);
    if (conn_port) *conn_port = myconn_port;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_payreq(EC_M_Payreq payreq1, EC_M_Payreq payreq2)
{
    if (!payreq1 || !payreq2) return 1;

    if (payreq1->currency != payreq2->currency
     || payreq1->amount != payreq2->amount
     || payreq1->timestamp != payreq2->timestamp
     || payreq1->shop_bankID != payreq2->shop_bankID
     || strcmp(payreq1->shop_accID, payreq2->shop_accID)
     || strcmp(payreq1->descr, payreq2->descr)
     || strcmp(payreq1->conn_host, payreq2->conn_host)
     || payreq1->conn_port != payreq2->conn_port)
	return 1;

    return 0;
}

void EC_M_free_payreq(EC_M_Payreq payreq)
{
    if (payreq) {
	if (payreq->shop_accID) EC_G_free(payreq->shop_accID);
	if (payreq->descr) EC_G_free(payreq->descr);
	if (payreq->conn_host) EC_G_free(payreq->conn_host);
	EC_G_free(payreq);
    }
}

EC_Errno EC_M_compile_payreq(EC_M_Payreq payreq, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!payreq || !payreq->shop_accID || !payreq->descr || !payreq->conn_host
	|| !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_PAYREQ, msg);
    if (!err) err = EC_M_compile_int(payreq->currency, msg);
    if (!err) err = EC_M_compile_int(payreq->amount, msg);
    if (!err) err = EC_M_compile_time(payreq->timestamp, msg);
    if (!err) err = EC_M_compile_int(payreq->shop_bankID, msg);
    if (!err) err = EC_M_compile_string(payreq->shop_accID, msg);
    if (!err) err = EC_M_compile_string(payreq->descr, msg);
    if (!err) err = EC_M_compile_string(payreq->conn_host, msg);
    if (!err) err = EC_M_compile_int(payreq->conn_port, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_payreq(EC_M_Payreq *payreq, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Currency currency;
    UInt32 amount;
    time_t timestamp;
    UInt32 shop_bankID;
    char *shop_accID = NULL;
    char *descr = NULL;
    char *conn_host = NULL;
    UInt32 conn_port;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_PAYREQ, msg);
    if (!err) err = EC_M_decompile_int(&currency, msg);
    if (!err) err = EC_M_decompile_int(&amount, msg);
    if (!err) err = EC_M_decompile_time(&timestamp, msg);
    if (!err) err = EC_M_decompile_int(&shop_bankID, msg);
    if (!err) err = EC_M_decompile_string(&shop_accID, msg);
    if (!err) err = EC_M_decompile_string(&descr, msg);
    if (!err) err = EC_M_decompile_string(&conn_host, msg);
    if (!err) err = EC_M_decompile_int(&conn_port, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && payreq) {
	*payreq = EC_M_new_payreq(currency, amount, timestamp, shop_bankID,
				    shop_accID, descr, conn_host, conn_port);
	if (!*payreq) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    if (shop_accID) EC_G_free(shop_accID);
    if (descr) EC_G_free(descr);
    if (conn_host) EC_G_free(conn_host);
    return err;
}

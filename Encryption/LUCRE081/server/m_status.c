#include "lucre.h"

/*
   status =
     [
       int	?? ; maybe state? = 2
       int	?? ; = 0
       int	?? ; = 0
       int	msg_seq
       int	wd_seq
       time	nextstamp
       int	balance
       int	cash
       int	?? ; = 0
     ]
 */

EC_M_Status EC_M_new_status(UInt32 msg_seq, UInt32 wd_seq,
    time_t nextstamp, UInt32 balance, UInt32 cash)
{
    EC_M_Status newstatus;

    newstatus = (EC_M_Status) EC_G_malloc(sizeof(struct EC_M_Status_s));
    if (!newstatus) return newstatus;

    newstatus->msg_seq = msg_seq;
    newstatus->wd_seq = wd_seq;
    newstatus->nextstamp = nextstamp;
    newstatus->balance = balance;
    newstatus->cash = cash;
    return newstatus;
}

EC_M_Status EC_M_clone_status(EC_M_Status status)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Status newstatus;
    UInt32 msg_seq;
    UInt32 wd_seq;
    time_t nextstamp;
    UInt32 balance;
    UInt32 cash;
    
    err = EC_M_examine_status(status, &msg_seq, &wd_seq, &nextstamp,
	&balance, &cash);
    if (!err) {
	newstatus = EC_M_new_status(msg_seq, wd_seq, nextstamp,
	    balance, cash);
	if (newstatus) return newstatus;
    }

    return NULL;
}

EC_Errno EC_M_examine_status(EC_M_Status status, UInt32 *msg_seq,
    UInt32 *wd_seq, time_t *nextstamp, UInt32 *balance, UInt32 *cash)
{ 
    UInt32 mymsg_seq;
    UInt32 mywd_seq;
    time_t mynextstamp;
    UInt32 mybalance;
    UInt32 mycash;

    if (!status) return EC_ERR_INTERNAL;

    mymsg_seq = status->msg_seq;
    mywd_seq = status->wd_seq;
    mynextstamp = status->nextstamp;
    mybalance = status->balance;
    mycash = status->cash;

    /* All OK */
    if (msg_seq) *msg_seq = mymsg_seq;
    if (wd_seq) *wd_seq = mywd_seq;
    if (nextstamp) *nextstamp = mynextstamp;
    if (balance) *balance = mybalance;
    if (cash) *cash = mycash;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_status(EC_M_Status status1, EC_M_Status status2)
{
    if (!status1 || !status2) return 1;

    if (status1->msg_seq != status2->msg_seq
     || status1->wd_seq != status2->wd_seq
     || status1->nextstamp != status2->nextstamp
     || status1->balance != status2->balance
     || status1->cash != status2->cash)
	return 1;

    return 0;
}

void EC_M_free_status(EC_M_Status status)
{
    if (status) {
	EC_G_free(status);
    }
}

EC_Errno EC_M_compile_status(EC_M_Status status, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!status || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_STATUS, msg);
    if (!err) err = EC_M_compile_int(2, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_int(status->msg_seq, msg);
    if (!err) err = EC_M_compile_int(status->wd_seq, msg);
    if (!err) err = EC_M_compile_time(status->nextstamp, msg);
    if (!err) err = EC_M_compile_int(status->balance, msg);
    if (!err) err = EC_M_compile_int(status->cash, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_status(EC_M_Status *status, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 msg_seq;
    UInt32 wd_seq;
    time_t nextstamp;
    UInt32 balance;
    UInt32 cash;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_STATUS, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(&msg_seq, msg);
    if (!err) err = EC_M_decompile_int(&wd_seq, msg);
    if (!err) err = EC_M_decompile_time(&nextstamp, msg);
    if (!err) err = EC_M_decompile_int(&balance, msg);
    if (!err) err = EC_M_decompile_int(&cash, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && status) {
	*status = EC_M_new_status(msg_seq, wd_seq, nextstamp, balance, cash);
	if (!*status) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

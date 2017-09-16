#include "lucre.h"

/*
   bank_repl =
     [
       int	userID
       int	msg_seq
       time	reftime
       time	timestamp
     ]
 */

EC_M_Bank_repl EC_M_new_bank_repl(UInt32 userID, UInt32 msg_seq,
    time_t reftime, time_t timestamp)
{
    EC_M_Bank_repl newhdr;

    newhdr = (EC_M_Bank_repl) EC_G_malloc(sizeof(struct EC_M_Bank_repl_s));
    if (!newhdr) return newhdr;

    newhdr->userID = userID;
    newhdr->msg_seq = msg_seq;
    newhdr->reftime = reftime;
    newhdr->timestamp = timestamp;
    return newhdr;
}

EC_M_Bank_repl EC_M_clone_bank_repl(EC_M_Bank_repl bank_repl)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Bank_repl newbank_repl;
    UInt32 userID;
    UInt32 msg_seq;
    time_t reftime;
    time_t timestamp;
    
    err = EC_M_examine_bank_repl(bank_repl, &userID, &msg_seq, &reftime,
	&timestamp);
    if (!err) {
	newbank_repl = EC_M_new_bank_repl(userID, msg_seq, reftime,
	    timestamp);
	if (newbank_repl) return newbank_repl;
    }

    return NULL;
}

EC_Errno EC_M_examine_bank_repl(EC_M_Bank_repl bank_repl, UInt32 *userID,
    UInt32 *msg_seq, time_t *reftime, time_t *timestamp)
{ 
    UInt32 myuserID;
    UInt32 mymsg_seq;
    time_t myreftime;
    time_t mytimestamp;

    if (!bank_repl) return EC_ERR_INTERNAL;

    myuserID = bank_repl->userID;
    mymsg_seq = bank_repl->msg_seq;
    myreftime = bank_repl->reftime;
    mytimestamp = bank_repl->timestamp;

    /* All OK */
    if (userID) *userID = myuserID;
    if (msg_seq) *msg_seq = mymsg_seq;
    if (reftime) *reftime = myreftime;
    if (timestamp) *timestamp = mytimestamp;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_bank_repl(EC_M_Bank_repl bank_repl1, EC_M_Bank_repl bank_repl2)
{
    if (!bank_repl1 || !bank_repl2) return 1;

    if (bank_repl1->userID != bank_repl2->userID
     || bank_repl1->msg_seq != bank_repl2->msg_seq
     || bank_repl1->reftime != bank_repl2->reftime
     || bank_repl1->timestamp != bank_repl2->timestamp)
	return 1;

    return 0;
}

void EC_M_free_bank_repl(EC_M_Bank_repl bank_repl)
{
    if (bank_repl) {
	EC_G_free(bank_repl);
    }
}

EC_Errno EC_M_compile_bank_repl(EC_M_Bank_repl bank_repl, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!bank_repl || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_BANK_REPL, msg);
    if (!err) err = EC_M_compile_int(bank_repl->userID, msg);
    if (!err) err = EC_M_compile_int(bank_repl->msg_seq, msg);
    if (!err) err = EC_M_compile_time(bank_repl->reftime, msg);
    if (!err) err = EC_M_compile_time(bank_repl->timestamp, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_bank_repl(EC_M_Bank_repl *bank_repl, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 userID;
    UInt32 msg_seq;
    time_t reftime;
    time_t timestamp;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_BANK_REPL, msg);
    if (!err) err = EC_M_decompile_int(&userID, msg);
    if (!err) err = EC_M_decompile_int(&msg_seq, msg);
    if (!err) err = EC_M_decompile_time(&reftime, msg);
    if (!err) err = EC_M_decompile_time(&timestamp, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && bank_repl) {
	*bank_repl = EC_M_new_bank_repl(userID, msg_seq, reftime, timestamp);
	if (!*bank_repl) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

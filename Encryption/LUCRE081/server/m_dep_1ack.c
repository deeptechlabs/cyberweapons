#include "lucre.h"

/*
   dep_1ack =
     [
       int	seqno
       int	result	; 3 = accept  4 = reject
       int	amount	; or reason, if rejected
     ]
 */

EC_M_Dep_1ack EC_M_new_dep_1ack(UInt32 seqno, UInt32 result, UInt32 amount)
{
    EC_M_Dep_1ack newdep_1ack;

    newdep_1ack = (EC_M_Dep_1ack) EC_G_malloc(sizeof(struct EC_M_Dep_1ack_s));
    if (!newdep_1ack) return newdep_1ack;

    newdep_1ack->seqno = seqno;
    newdep_1ack->result = result;
    newdep_1ack->amount = amount;
    return newdep_1ack;
}

EC_M_Dep_1ack EC_M_clone_dep_1ack(EC_M_Dep_1ack dep_1ack)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Dep_1ack newdep_1ack;
    UInt32 seqno;
    UInt32 result;
    UInt32 amount;
    
    err = EC_M_examine_dep_1ack(dep_1ack, &seqno, &result, &amount);
    if (!err) {
	newdep_1ack = EC_M_new_dep_1ack(seqno, result, amount);
	if (newdep_1ack) return newdep_1ack;
    }

    return NULL;
}

EC_Errno EC_M_examine_dep_1ack(EC_M_Dep_1ack dep_1ack, UInt32 *seqno,
    UInt32 *result, UInt32 *amount)
{ 
    UInt32 myseqno;
    UInt32 myresult;
    UInt32 myamount;

    if (!dep_1ack) return EC_ERR_INTERNAL;

    myseqno = dep_1ack->seqno;
    myresult = dep_1ack->result;
    myamount = dep_1ack->amount;

    /* All OK */
    if (seqno) *seqno = myseqno;
    if (result) *result = myresult;
    if (amount) *amount = myamount;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_dep_1ack(EC_M_Dep_1ack dep_1ack1, EC_M_Dep_1ack dep_1ack2)
{
    if (!dep_1ack1 || !dep_1ack2) return 1;

    if (dep_1ack1->seqno != dep_1ack2->seqno
     || dep_1ack1->result != dep_1ack2->result
     || dep_1ack1->amount != dep_1ack2->amount)
	return 1;

    return 0;
}

void EC_M_free_dep_1ack(EC_M_Dep_1ack dep_1ack)
{
    if (dep_1ack) {
	EC_G_free(dep_1ack);
    }
}

EC_Errno EC_M_compile_dep_1ack(EC_M_Dep_1ack dep_1ack, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!dep_1ack || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_DEP_1ACK, msg);
    if (!err) err = EC_M_compile_int(dep_1ack->seqno, msg);
    if (!err) err = EC_M_compile_int(dep_1ack->result, msg);
    if (!err) err = EC_M_compile_int(dep_1ack->amount, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_dep_1ack(EC_M_Dep_1ack *dep_1ack, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 seqno;
    UInt32 result;
    UInt32 amount;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_DEP_1ACK, msg);
    if (!err) err = EC_M_decompile_int(&seqno, msg);
    if (!err) err = EC_M_decompile_int(&result, msg);
    if (!err) err = EC_M_decompile_int(&amount, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && dep_1ack) {
	*dep_1ack = EC_M_new_dep_1ack(seqno, result, amount);
	if (!*dep_1ack) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

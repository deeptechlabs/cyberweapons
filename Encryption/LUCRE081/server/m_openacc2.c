#include "lucre.h"

/*
   openacc2 =
     [
        int     userID
        int     msg_seq
        MPI     N
        int     protocol
     ]
 */

EC_M_Openacc2 EC_M_new_openacc2(UInt32 userID, UInt32 msg_seq,
    BIGNUM *n, EC_M_Protocol protocol)
{
    EC_M_Openacc2 newopenacc2;

    if (!n) return NULL;
    newopenacc2 = (EC_M_Openacc2) EC_G_malloc(sizeof(struct EC_M_Openacc2_s));
    if (!newopenacc2) return newopenacc2;

    newopenacc2->userID = userID;
    newopenacc2->msg_seq = msg_seq;
    newopenacc2->n = n;
    newopenacc2->protocol = protocol;
    return newopenacc2;
}

EC_M_Openacc2 EC_M_clone_openacc2(EC_M_Openacc2 openacc2)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Openacc2 newopenacc2;
    UInt32 userID;
    UInt32 msg_seq;
    BIGNUM *n = NULL;
    UInt32 protocol;
    
    err = EC_M_examine_openacc2(openacc2, &userID, &msg_seq, &n, &protocol);
    if (!err) {
	newopenacc2 = EC_M_new_openacc2(userID, msg_seq, n, protocol);
	if (newopenacc2) return newopenacc2;
    }

    EC_M_free_MPI(n);
    return NULL;
}

EC_Errno EC_M_examine_openacc2(EC_M_Openacc2 openacc2, UInt32 *userID,
    UInt32 *msg_seq, BIGNUM **n, UInt32 *protocol)
{ 
    UInt32 myuserID;
    UInt32 mymsg_seq;
    BIGNUM *myn;
    UInt32 myprotocol;

    if (!openacc2) return EC_ERR_INTERNAL;

    myuserID = openacc2->userID;
    mymsg_seq = openacc2->msg_seq;
    myn = EC_M_clone_MPI(openacc2->n);
    myprotocol = openacc2->protocol;

    if (!myn) {
	/* Didn't copy properly; abort */
	EC_M_free_MPI(myn);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (userID) *userID = myuserID;
    if (msg_seq) *msg_seq = mymsg_seq;
    if (n) *n = myn; else EC_M_free_MPI(myn);
    if (protocol) *protocol = myprotocol;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_openacc2(EC_M_Openacc2 openacc21, EC_M_Openacc2 openacc22)
{
    if (!openacc21 || !openacc22) return 1;

    if (openacc21->userID != openacc22->userID
     || openacc21->msg_seq != openacc22->msg_seq
     || EC_M_cmp_MPI(openacc21->n, openacc22->n)
     || openacc21->protocol != openacc22->protocol)
	return 1;

    return 0;
}

void EC_M_free_openacc2(EC_M_Openacc2 openacc2)
{
    if (openacc2) {
	EC_M_free_MPI(openacc2->n);
	EC_G_free(openacc2);
    }
}

EC_Errno EC_M_compile_openacc2(EC_M_Openacc2 openacc2, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!openacc2 || !openacc2->n || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_OPENACC2, msg);
    if (!err) err = EC_M_compile_int(openacc2->userID, msg);
    if (!err) err = EC_M_compile_int(openacc2->msg_seq, msg);
    if (!err) err = EC_M_compile_MPI(openacc2->n, msg);
    if (!err) err = EC_M_compile_int(openacc2->protocol, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_openacc2(EC_M_Openacc2 *openacc2, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 userID;
    UInt32 msg_seq;
    BIGNUM *n = NULL;
    UInt32 protocol;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_OPENACC2, msg);
    if (!err) err = EC_M_decompile_int(&userID, msg);
    if (!err) err = EC_M_decompile_int(&msg_seq, msg);
    if (!err) err = EC_M_decompile_MPI(&n, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && openacc2) {
	*openacc2 = EC_M_new_openacc2(userID, msg_seq, n, protocol);
	if (!*openacc2) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(n);
    return err;
}

#include "lucre.h"

/*
   sigmsg =
     [
       int	algorithm
       MPI	signature
     ]
   siglength =
     [
       int	length
     ]
   msg
 */

EC_M_Sigmsg EC_M_new_sigmsg(EC_M_Sigalg algorithm, BIGNUM *signature,
    EC_M_Msg msg)
{
    EC_M_Sigmsg newsigmsg;

    if (!signature || !msg) return NULL;
    newsigmsg = (EC_M_Sigmsg) EC_G_malloc(sizeof(struct EC_M_Sigmsg_s));
    if (!newsigmsg) return newsigmsg;

    newsigmsg->algorithm = algorithm;
    newsigmsg->signature = signature;
    newsigmsg->msg = msg;
    return newsigmsg;
}

EC_M_Sigmsg EC_M_clone_sigmsg(EC_M_Sigmsg sigmsg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Sigmsg newsigmsg;
    EC_M_Sigalg algorithm;
    BIGNUM *signature = NULL;
    EC_M_Msg msg = NULL;
    
    err = EC_M_examine_sigmsg(sigmsg, &algorithm, &signature, &msg);
    if (!err) {
	newsigmsg = EC_M_new_sigmsg(algorithm, signature, msg);
	if (newsigmsg) return newsigmsg;
    }

    EC_M_free_MPI(signature);
    EC_M_free_msg(msg);
    return NULL;
}

EC_Errno EC_M_examine_sigmsg(EC_M_Sigmsg sigmsg, EC_M_Sigalg *algorithm,
    BIGNUM **signature, EC_M_Msg *msg)
{ 
    EC_M_Sigalg myalgorithm;
    BIGNUM *mysignature;
    EC_M_Msg mymsg;

    if (!sigmsg) return EC_ERR_INTERNAL;

    myalgorithm = sigmsg->algorithm;
    mysignature = EC_M_clone_MPI(sigmsg->signature);
    mymsg = EC_M_clone_msg(sigmsg->msg);

    if (!mysignature || !mymsg) {
	/* Didn't copy properly; abort */
	EC_M_free_MPI(mysignature);
	EC_M_free_msg(mymsg);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (algorithm) *algorithm = myalgorithm;
    if (signature) *signature = mysignature; else EC_M_free_MPI(mysignature);
    if (msg) *msg = mymsg; else EC_M_free_msg(mymsg);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_sigmsg(EC_M_Sigmsg sigmsg1, EC_M_Sigmsg sigmsg2)
{
    if (!sigmsg1 || !sigmsg2) return 1;

    if (sigmsg1->algorithm != sigmsg2->algorithm
     || EC_M_cmp_MPI(sigmsg1->signature, sigmsg2->signature)
     || EC_M_cmp_msg(sigmsg1->msg, sigmsg2->msg))
	return 1;

    return 0;
}

void EC_M_free_sigmsg(EC_M_Sigmsg sigmsg)
{
    if (sigmsg) {
	EC_M_free_MPI(sigmsg->signature);
	EC_M_free_msg(sigmsg->msg);
	EC_G_free(sigmsg);
    }
}

EC_Errno EC_M_compile_sigmsg(EC_M_Sigmsg sigmsg, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!sigmsg || !sigmsg->signature || !sigmsg->msg || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_SIGMSG, msg);
    if (!err) err = EC_M_compile_int(sigmsg->algorithm, msg);
    if (!err) err = EC_M_compile_MPI(sigmsg->signature, msg);
    if (!err) err = EC_M_compile_eor(msg);
    if (!err) err = EC_M_compile_sor(EC_M_REC_SIGLEN, msg);
    if (!err) err = EC_M_compile_int(sigmsg->msg->end - sigmsg->msg->begin,
					msg);
    if (!err) err = EC_M_compile_eor(msg);
    if (!err) err = EC_M_append_msg(sigmsg->msg->data + sigmsg->msg->begin,
				    sigmsg->msg->end - sigmsg->msg->begin,
				    msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_sigmsg(EC_M_Sigmsg *sigmsg, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Sigalg algorithm;
    BIGNUM *signature = NULL;
    UInt32 siglen;
    EC_M_Msg submsg = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_SIGMSG, msg);
    if (!err) err = EC_M_decompile_int(&algorithm, msg);
    if (!err) err = EC_M_decompile_MPI(&signature, msg);
    if (!err) err = EC_M_decompile_eor(msg);
    if (!err) err = EC_M_decompile_sor(EC_M_REC_SIGLEN, msg);
    if (!err) err = EC_M_decompile_int(&siglen, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Read the next siglen bytes and make it its own message */
    if (!err) {
	submsg = EC_M_new_msg();
	if (!submsg) err = EC_ERR_INTERNAL;
	else if (msg->begin + siglen > msg->end) err = EC_ERR_INTERNAL;
	else {
	    err = EC_M_append_msg(msg->data + msg->begin, siglen, submsg);
	    msg->begin += siglen;
	}
    }

    /* Did it work? */
    if (!err && sigmsg) {
	*sigmsg = EC_M_new_sigmsg(algorithm, signature, submsg);
	if (!*sigmsg) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(signature);
    EC_M_free_msg(submsg);
    return err;
}

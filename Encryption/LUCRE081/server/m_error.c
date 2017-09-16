#include "lucre.h"

/*
   error =
     [
        int	unknown		; = 0
        int	unknown		; = 0
        int	errno
        int	unknown		; = 0
     ]
 */

EC_M_Error EC_M_new_error(EC_M_Errno errno)
{
    EC_M_Error newerror;

    newerror = (EC_M_Error) EC_G_malloc(sizeof(struct EC_M_Error_s));
    if (!newerror) return newerror;

    newerror->errno = errno;
    return newerror;
}

EC_M_Error EC_M_clone_error(EC_M_Error error)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Error newerror;
    EC_M_Errno errno;
    
    err = EC_M_examine_error(error, &errno);
    if (!err) {
	newerror = EC_M_new_error(errno);
	if (newerror) return newerror;
    }

    return NULL;
}

EC_Errno EC_M_examine_error(EC_M_Error error, EC_M_Errno *errno)
{ 
    EC_M_Errno myerrno;

    if (!error) return EC_ERR_INTERNAL;

    myerrno = error->errno;

    /* All OK */
    if (errno) *errno = myerrno;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_error(EC_M_Error error1, EC_M_Error error2)
{
    if (!error1 || !error2) return 1;

    if (error1->errno != error2->errno)
	return 1;

    return 0;
}

void EC_M_free_error(EC_M_Error error)
{
    if (error) {
	EC_G_free(error);
    }
}

EC_Errno EC_M_compile_error(EC_M_Error error, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!error || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_ERROR, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_int(error->errno, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_error(EC_M_Error *error, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Errno errno;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_ERROR, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(&errno, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && error) {
	*error = EC_M_new_error(errno);
	if (!*error) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

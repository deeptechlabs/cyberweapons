#include "lucre.h"

/* SETUP_REQ messages contain no information */

EC_M_Setup_req EC_M_new_setup_req()
{
    return 1;
}

EC_M_Setup_req EC_M_clone_setup_req(EC_M_Setup_req setup_req)
{
    return setup_req ? 1 : 0;
}

EC_Errno EC_M_examine_setup_req(EC_M_Setup_req setup_req)
{ 
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_setup_req(EC_M_Setup_req setup_req1, EC_M_Setup_req setup_req2)
{
    if (!setup_req1 || !setup_req2) return 1;

    return 0;
}

void EC_M_free_setup_req(EC_M_Setup_req setup_req)
{
    return;
}

EC_Errno EC_M_compile_setup_req(EC_M_Setup_req setup_req, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!setup_req || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_SETUP_REQ, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_setup_req(EC_M_Setup_req *setup_req, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_SETUP_REQ, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && setup_req) {
	*setup_req = EC_M_new_setup_req();
	if (!*setup_req) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

#include "lucre.h"

/*
   SETUP =
     [
       sigmsg
     ]
 */

EC_M_Setup EC_M_new_setup(EC_M_Sigmsg sigmsg)
{
    EC_M_Setup newsetup;

    if (!sigmsg) return NULL;
    newsetup = (EC_M_Setup) EC_G_malloc(sizeof(struct EC_M_Setup_s));
    if (!newsetup) return newsetup;

    newsetup->sigmsg = sigmsg;
    return newsetup;
}

EC_M_Setup EC_M_clone_setup(EC_M_Setup setup)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Setup newsetup;
    EC_M_Sigmsg sigmsg = NULL;
    
    err = EC_M_examine_setup(setup, &sigmsg);
    if (!err) {
	newsetup = EC_M_new_setup(sigmsg);
	if (newsetup) return newsetup;
    }

    EC_M_free_sigmsg(sigmsg);
    return NULL;
}

EC_Errno EC_M_examine_setup(EC_M_Setup setup, EC_M_Sigmsg *sigmsg)
{ 
    EC_M_Sigmsg mysigmsg;

    if (!setup) return EC_ERR_INTERNAL;

    mysigmsg = EC_M_clone_sigmsg(setup->sigmsg);

    if (!mysigmsg) {
	/* Didn't copy properly; abort */
	EC_M_free_sigmsg(mysigmsg);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (sigmsg) *sigmsg = mysigmsg; else EC_M_free_sigmsg(mysigmsg);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_setup(EC_M_Setup setup1, EC_M_Setup setup2)
{
    if (!setup1 || !setup2) return 1;

    if (EC_M_cmp_sigmsg(setup1->sigmsg, setup2->sigmsg))
	return 1;

    return 0;
}

void EC_M_free_setup(EC_M_Setup setup)
{
    if (setup) {
	EC_M_free_sigmsg(setup->sigmsg);
	EC_G_free(setup);
    }
}

EC_Errno EC_M_compile_setup(EC_M_Setup setup, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!setup || !setup->sigmsg || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_SETUP, msg);
    if (!err) err = EC_M_compile_sigmsg(setup->sigmsg, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_setup(EC_M_Setup *setup, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Sigmsg sigmsg = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_SETUP, msg);
    if (!err) err = EC_M_decompile_sigmsg(&sigmsg, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && setup) {
	*setup = EC_M_new_setup(sigmsg);
	if (!*setup) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_sigmsg(sigmsg);
    return err;
}

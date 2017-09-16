#include "lucre.h"

/*
   PROT_SETUP =
     [
       int	protocol
     ]
 */

EC_M_Prot_setup EC_M_new_prot_setup(EC_M_Protocol protocol)
{
    EC_M_Prot_setup newprot_setup;

    newprot_setup =
	(EC_M_Prot_setup) EC_G_malloc(sizeof(struct EC_M_Prot_setup_s));
    if (!newprot_setup) return newprot_setup;

    newprot_setup->protocol = protocol;
    return newprot_setup;
}

EC_M_Prot_setup EC_M_clone_prot_setup(EC_M_Prot_setup prot_setup)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Prot_setup newprot_setup;
    EC_M_Protocol protocol;
    
    err = EC_M_examine_prot_setup(prot_setup, &protocol);
    if (!err) {
	newprot_setup = EC_M_new_prot_setup(protocol);
	if (newprot_setup) return newprot_setup;
    }

    return NULL;
}

EC_Errno EC_M_examine_prot_setup(EC_M_Prot_setup prot_setup, EC_M_Protocol *protocol)
{ 
    EC_M_Protocol myprotocol;

    if (!prot_setup) return EC_ERR_INTERNAL;

    myprotocol = prot_setup->protocol;

    /* All OK */
    if (protocol) *protocol = myprotocol;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_prot_setup(EC_M_Prot_setup prot_setup1, EC_M_Prot_setup prot_setup2)
{
    if (!prot_setup1 || !prot_setup2) return 1;

    if (prot_setup1->protocol != prot_setup2->protocol)
	return 1;

    return 0;
}

void EC_M_free_prot_setup(EC_M_Prot_setup prot_setup)
{
    if (prot_setup) {
	EC_G_free(prot_setup);
    }
}

EC_Errno EC_M_compile_prot_setup(EC_M_Prot_setup prot_setup, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!prot_setup || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_PROT_SETUP, msg);
    if (!err) err = EC_M_compile_int(prot_setup->protocol, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_prot_setup(EC_M_Prot_setup *prot_setup, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Protocol protocol;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_PROT_SETUP, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && prot_setup) {
	*prot_setup = EC_M_new_prot_setup(protocol);
	if (!*prot_setup) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

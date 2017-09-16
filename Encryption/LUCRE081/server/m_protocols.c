#include "lucre.h"

/*
   protocols =
     [
       prot_setup
       ...
     ]
 */

EC_M_Protocols EC_M_new_protocols(UInt32 numprots, EC_M_Prot_setup *prot_setup)
{
    EC_M_Protocols newprotocols;

    if (numprots && !prot_setup) return NULL;
    newprotocols = (EC_M_Protocols) EC_G_malloc(sizeof(struct EC_M_Protocols_s));
    if (!newprotocols) return newprotocols;

    newprotocols->numprots = numprots;
    newprotocols->prot_setup = prot_setup;
    return newprotocols;
}

EC_M_Protocols EC_M_clone_protocols(EC_M_Protocols protocols)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Protocols newprotocols;
    UInt32 numprots = 0;
    EC_M_Prot_setup *prot_setup = NULL;

    int i;
    
    err = EC_M_examine_protocols(protocols, &numprots, &prot_setup);
    if (!err) {
	newprotocols = EC_M_new_protocols(numprots, prot_setup);
	if (newprotocols) return newprotocols;
    }

    for(i=0;i<numprots;++i)
	if (prot_setup) EC_M_free_prot_setup(prot_setup[i]);
    if (prot_setup) EC_G_free(prot_setup);

    return NULL;
}

EC_Errno EC_M_examine_protocols(EC_M_Protocols protocols, UInt32 *numprots,
    EC_M_Prot_setup **prot_setup)
{ 
    UInt32 mynumprots;
    EC_M_Prot_setup *myprot_setup;

    int i;
    int seenbad = 0;

    if (!protocols) return EC_ERR_INTERNAL;

    mynumprots = protocols->numprots;
    myprot_setup =
	(EC_M_Prot_setup *)EC_G_malloc(sizeof(EC_M_Prot_setup)*mynumprots);
    if (myprot_setup) for(i=0;i<mynumprots;++i) {
	myprot_setup[i] = EC_M_clone_prot_setup(protocols->prot_setup[i]);
	if (!myprot_setup[i]) seenbad = 1;
    }

    if (!myprot_setup || seenbad) {
	/* Didn't copy properly; abort */
	for(i=0;i<mynumprots;++i)
	    if (myprot_setup) EC_M_free_prot_setup(myprot_setup[i]);
	if (myprot_setup) EC_G_free(myprot_setup);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (numprots) *numprots = mynumprots;
    if (prot_setup) *prot_setup = myprot_setup; else {
	for(i=0;i<mynumprots;++i) EC_M_free_prot_setup(myprot_setup[i]);
	EC_G_free(myprot_setup);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_protocols(EC_M_Protocols protocols1, EC_M_Protocols protocols2)
{
    int i;

    if (!protocols1 || !protocols2) return 1;

    if (protocols1->numprots != protocols2->numprots)
	return 1;

    if (protocols1->numprots &&
	(!protocols1->prot_setup || !protocols2->prot_setup))
	return 1;

    for(i=0;i<protocols1->numprots;++i) {
	if (EC_M_cmp_prot_setup(protocols1->prot_setup[i],
	    protocols2->prot_setup[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_protocols(EC_M_Protocols protocols)
{
    int i;

    if (protocols) {
	for(i=0;i<protocols->numprots;++i)
	    if (protocols->prot_setup)
		EC_M_free_prot_setup(protocols->prot_setup[i]);
	if (protocols->prot_setup) EC_G_free(protocols->prot_setup);
	EC_G_free(protocols);
    }
}

EC_Errno EC_M_compile_protocols(EC_M_Protocols protocols, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!protocols || (protocols->numprots && !protocols->prot_setup) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_PROTOCOLS, msg);
    for(i=0;i<protocols->numprots;++i)
	if (!err) err = EC_M_compile_prot_setup(protocols->prot_setup[i], msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_protocols(EC_M_Protocols *protocols, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 numprots = 0;
    EC_M_Prot_setup *prot_setup = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_PROTOCOLS, msg);
    while(!err) {
	if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
	if (!err) if (fieldtype != EC_M_FIELD_SOR ||
			rectype != EC_M_REC_PROT_SETUP) break;
	if (!err) {
	    EC_M_Prot_setup *newprot_setup =
		(EC_M_Prot_setup *)EC_G_realloc(prot_setup,
		sizeof(EC_M_Prot_setup)*(numprots+1));
	    if (!newprot_setup) {
		if (prot_setup) EC_G_free(prot_setup);
		err = EC_ERR_INTERNAL;
	    } else {
		prot_setup = newprot_setup;
	    }
	}
	if (!err) err = EC_M_decompile_prot_setup(&prot_setup[numprots], msg);
	if (!err) ++numprots;
    }
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && protocols) {
	*protocols = EC_M_new_protocols(numprots, prot_setup);
	if (!*protocols) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numprots;++i)
	if (prot_setup) EC_M_free_prot_setup(prot_setup[i]);
    if (prot_setup) EC_G_free(prot_setup);
    return err;
}

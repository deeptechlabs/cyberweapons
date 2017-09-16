#include "lucre.h"

/*
   DEP_ACK =
     [
       dep_1ack
       ...
     ]
 */

EC_M_Dep_ack EC_M_new_dep_ack(UInt32 numacks, EC_M_Dep_1ack *dep_1ack)
{
    EC_M_Dep_ack newdep_ack;

    if (numacks && !dep_1ack) return NULL;
    newdep_ack = (EC_M_Dep_ack) EC_G_malloc(sizeof(struct EC_M_Dep_ack_s));
    if (!newdep_ack) return newdep_ack;

    newdep_ack->numacks = numacks;
    newdep_ack->dep_1ack = dep_1ack;
    return newdep_ack;
}

EC_M_Dep_ack EC_M_clone_dep_ack(EC_M_Dep_ack dep_ack)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Dep_ack newdep_ack;
    UInt32 numacks = 0;
    EC_M_Dep_1ack *dep_1ack = NULL;

    int i;
    
    err = EC_M_examine_dep_ack(dep_ack, &numacks, &dep_1ack);
    if (!err) {
	newdep_ack = EC_M_new_dep_ack(numacks, dep_1ack);
	if (newdep_ack) return newdep_ack;
    }

    for(i=0;i<numacks;++i)
	if (dep_1ack) EC_M_free_dep_1ack(dep_1ack[i]);
    if (dep_1ack) EC_G_free(dep_1ack);

    return NULL;
}

EC_Errno EC_M_examine_dep_ack(EC_M_Dep_ack dep_ack, UInt32 *numacks,
    EC_M_Dep_1ack **dep_1ack)
{ 
    UInt32 mynumacks;
    EC_M_Dep_1ack *mydep_1ack;

    int i;
    int seenbad = 0;

    if (!dep_ack) return EC_ERR_INTERNAL;

    mynumacks = dep_ack->numacks;
    mydep_1ack =
	(EC_M_Dep_1ack *)EC_G_malloc(sizeof(EC_M_Dep_1ack)*mynumacks);
    if (mydep_1ack) for(i=0;i<mynumacks;++i) {
	mydep_1ack[i] = EC_M_clone_dep_1ack(dep_ack->dep_1ack[i]);
	if (!mydep_1ack[i]) seenbad = 1;
    }

    if (!mydep_1ack || seenbad) {
	/* Didn't copy properly; abort */
	for(i=0;i<mynumacks;++i)
	    if (mydep_1ack) EC_M_free_dep_1ack(mydep_1ack[i]);
	if (mydep_1ack) EC_G_free(mydep_1ack);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (numacks) *numacks = mynumacks;
    if (dep_1ack) *dep_1ack = mydep_1ack; else {
	for(i=0;i<mynumacks;++i) EC_M_free_dep_1ack(mydep_1ack[i]);
	EC_G_free(mydep_1ack);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_dep_ack(EC_M_Dep_ack dep_ack1, EC_M_Dep_ack dep_ack2)
{
    int i;

    if (!dep_ack1 || !dep_ack2) return 1;

    if (dep_ack1->numacks != dep_ack2->numacks)
	return 1;

    if (dep_ack1->numacks &&
	(!dep_ack1->dep_1ack || !dep_ack2->dep_1ack))
	return 1;

    for(i=0;i<dep_ack1->numacks;++i) {
	if (EC_M_cmp_dep_1ack(dep_ack1->dep_1ack[i],
	    dep_ack2->dep_1ack[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_dep_ack(EC_M_Dep_ack dep_ack)
{
    int i;

    if (dep_ack) {
	for(i=0;i<dep_ack->numacks;++i)
	    if (dep_ack->dep_1ack)
		EC_M_free_dep_1ack(dep_ack->dep_1ack[i]);
	if (dep_ack->dep_1ack) EC_G_free(dep_ack->dep_1ack);
	EC_G_free(dep_ack);
    }
}

EC_Errno EC_M_compile_dep_ack(EC_M_Dep_ack dep_ack, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!dep_ack || (dep_ack->numacks && !dep_ack->dep_1ack) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_DEP_ACK, msg);
    for(i=0;i<dep_ack->numacks;++i)
	if (!err) err = EC_M_compile_dep_1ack(dep_ack->dep_1ack[i], msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_dep_ack(EC_M_Dep_ack *dep_ack, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 numacks = 0;
    EC_M_Dep_1ack *dep_1ack = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_DEP_ACK, msg);
    while(!err) {
	if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
	if (!err) if (fieldtype != EC_M_FIELD_SOR ||
			rectype != EC_M_REC_DEP_1ACK) break;
	if (!err) {
	    EC_M_Dep_1ack *newdep_1ack =
		(EC_M_Dep_1ack *)EC_G_realloc(dep_1ack,
		sizeof(EC_M_Dep_1ack)*(numacks+1));
	    if (!newdep_1ack) {
		if (dep_1ack) EC_G_free(dep_1ack);
		err = EC_ERR_INTERNAL;
	    } else {
		dep_1ack = newdep_1ack;
	    }
	}
	if (!err) err = EC_M_decompile_dep_1ack(&dep_1ack[numacks], msg);
	if (!err) ++numacks;
    }
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && dep_ack) {
	*dep_ack = EC_M_new_dep_ack(numacks, dep_1ack);
	if (!*dep_ack) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numacks;++i)
	if (dep_1ack) EC_M_free_dep_1ack(dep_1ack[i]);
    if (dep_1ack) EC_G_free(dep_1ack);
    return err;
}

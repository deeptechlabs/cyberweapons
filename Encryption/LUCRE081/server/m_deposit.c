#include "lucre.h"

/*
   deposit =
     [
       dep
       ...
     ]
 */

EC_M_Deposit EC_M_new_deposit(UInt32 numdeps, EC_M_Dep *dep)
{
    EC_M_Deposit newdeposit;

    if (numdeps && !dep) return NULL;
    newdeposit = (EC_M_Deposit) EC_G_malloc(sizeof(struct EC_M_Deposit_s));
    if (!newdeposit) return newdeposit;

    newdeposit->numdeps = numdeps;
    newdeposit->dep = dep;
    return newdeposit;
}

EC_M_Deposit EC_M_clone_deposit(EC_M_Deposit deposit)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Deposit newdeposit;
    UInt32 numdeps = 0;
    EC_M_Dep *dep = NULL;

    int i;
    
    err = EC_M_examine_deposit(deposit, &numdeps, &dep);
    if (!err) {
	newdeposit = EC_M_new_deposit(numdeps, dep);
	if (newdeposit) return newdeposit;
    }

    for(i=0;i<numdeps;++i)
	if (dep) EC_M_free_dep(dep[i]);
    if (dep) EC_G_free(dep);

    return NULL;
}

EC_Errno EC_M_examine_deposit(EC_M_Deposit deposit, UInt32 *numdeps,
    EC_M_Dep **dep)
{ 
    UInt32 mynumdeps;
    EC_M_Dep *mydep;

    int i;
    int seenbad = 0;

    if (!deposit) return EC_ERR_INTERNAL;

    mynumdeps = deposit->numdeps;
    mydep =
	(EC_M_Dep *)EC_G_malloc(sizeof(EC_M_Dep)*mynumdeps);
    if (mydep) for(i=0;i<mynumdeps;++i) {
	mydep[i] = EC_M_clone_dep(deposit->dep[i]);
	if (!mydep[i]) seenbad = 1;
    }

    if (!mydep || seenbad) {
	/* Didn't copy properly; abort */
	for(i=0;i<mynumdeps;++i)
	    if (mydep) EC_M_free_dep(mydep[i]);
	if (mydep) EC_G_free(mydep);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (numdeps) *numdeps = mynumdeps;
    if (dep) *dep = mydep; else {
	for(i=0;i<mynumdeps;++i) EC_M_free_dep(mydep[i]);
	EC_G_free(mydep);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_deposit(EC_M_Deposit deposit1, EC_M_Deposit deposit2)
{
    int i;

    if (!deposit1 || !deposit2) return 1;

    if (deposit1->numdeps != deposit2->numdeps)
	return 1;

    if (deposit1->numdeps &&
	(!deposit1->dep || !deposit2->dep))
	return 1;

    for(i=0;i<deposit1->numdeps;++i) {
	if (EC_M_cmp_dep(deposit1->dep[i],
	    deposit2->dep[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_deposit(EC_M_Deposit deposit)
{
    int i;

    if (deposit) {
	for(i=0;i<deposit->numdeps;++i)
	    if (deposit->dep)
		EC_M_free_dep(deposit->dep[i]);
	if (deposit->dep) EC_G_free(deposit->dep);
	EC_G_free(deposit);
    }
}

EC_Errno EC_M_compile_deposit(EC_M_Deposit deposit, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!deposit || (deposit->numdeps && !deposit->dep) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_DEPOSIT, msg);
    for(i=0;i<deposit->numdeps;++i)
	if (!err) err = EC_M_compile_dep(deposit->dep[i], msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_deposit(EC_M_Deposit *deposit, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 numdeps = 0;
    EC_M_Dep *dep = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_DEPOSIT, msg);
    while(!err) {
	if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
	if (!err) if (fieldtype != EC_M_FIELD_SOR ||
			rectype != EC_M_REC_DEP) break;
	if (!err) {
	    EC_M_Dep *newdep =
		(EC_M_Dep *)EC_G_realloc(dep,
		sizeof(EC_M_Dep)*(numdeps+1));
	    if (!newdep) {
		if (dep) EC_G_free(dep);
		err = EC_ERR_INTERNAL;
	    } else {
		dep = newdep;
	    }
	}
	if (!err) err = EC_M_decompile_dep(&dep[numdeps], msg);
	if (!err) ++numdeps;
    }
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && deposit) {
	*deposit = EC_M_new_deposit(numdeps, dep);
	if (!*deposit) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numdeps;++i)
	if (dep) EC_M_free_dep(dep[i]);
    if (dep) EC_G_free(dep);
    return err;
}

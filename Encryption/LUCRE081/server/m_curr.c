#include "lucre.h"

/*
   curr =
     [
       cinfo
       onl_curr
       ...
     ]
 */

EC_M_Curr EC_M_new_curr(UInt32 numcurrs, EC_M_Cinfo *cinfo,
    EC_M_Onl_curr *onl_curr)
{
    EC_M_Curr newcurr;

    if (numcurrs && (!cinfo || !onl_curr)) return NULL;
    newcurr = (EC_M_Curr) EC_G_malloc(sizeof(struct EC_M_Curr_s));
    if (!newcurr) return newcurr;

    newcurr->numcurrs = numcurrs;
    newcurr->cinfo = cinfo;
    newcurr->onl_curr = onl_curr;
    return newcurr;
}

EC_M_Curr EC_M_clone_curr(EC_M_Curr curr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Curr newcurr;
    UInt32 numcurrs = 0;
    EC_M_Cinfo *cinfo = NULL;
    EC_M_Onl_curr *onl_curr = NULL;

    int i;
    
    err = EC_M_examine_curr(curr, &numcurrs, &cinfo, &onl_curr);
    if (!err) {
	newcurr = EC_M_new_curr(numcurrs, cinfo, onl_curr);
	if (newcurr) return newcurr;
    }

    for(i=0;i<numcurrs;++i)
	if (cinfo) EC_M_free_cinfo(cinfo[i]);
    if (cinfo) EC_G_free(cinfo);
    for(i=0;i<numcurrs;++i)
	if (onl_curr) EC_M_free_onl_curr(onl_curr[i]);
    if (onl_curr) EC_G_free(onl_curr);

    return NULL;
}

EC_Errno EC_M_examine_curr(EC_M_Curr curr, UInt32 *numcurrs,
    EC_M_Cinfo **cinfo, EC_M_Onl_curr **onl_curr)
{ 
    UInt32 mynumcurrs;
    EC_M_Cinfo *mycinfo;
    EC_M_Onl_curr *myonl_curr;

    int i;
    int seenbad = 0;

    if (!curr) return EC_ERR_INTERNAL;

    mynumcurrs = curr->numcurrs;
    mycinfo = (EC_M_Cinfo *)EC_G_malloc(sizeof(EC_M_Cinfo)*mynumcurrs);
    if (mycinfo) for(i=0;i<mynumcurrs;++i) {
	mycinfo[i] = EC_M_clone_cinfo(curr->cinfo[i]);
	if (!mycinfo[i]) seenbad = 1;
    }
    myonl_curr = (EC_M_Onl_curr *)EC_G_malloc(sizeof(EC_M_Onl_curr)*mynumcurrs);
    if (myonl_curr) for(i=0;i<mynumcurrs;++i) {
	myonl_curr[i] = EC_M_clone_onl_curr(curr->onl_curr[i]);
	if (!myonl_curr[i]) seenbad = 1;
    }

    if (!mycinfo || !myonl_curr || seenbad) {
	/* Didn't copy properly; abort */
	for(i=0;i<mynumcurrs;++i)
	    if (mycinfo) EC_M_free_cinfo(mycinfo[i]);
	if (mycinfo) EC_G_free(mycinfo);
	for(i=0;i<mynumcurrs;++i)
	    if (myonl_curr) EC_M_free_onl_curr(myonl_curr[i]);
	if (myonl_curr) EC_G_free(myonl_curr);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (numcurrs) *numcurrs = mynumcurrs;
    if (cinfo) *cinfo = mycinfo; else {
	for(i=0;i<mynumcurrs;++i) EC_M_free_cinfo(mycinfo[i]);
	EC_G_free(mycinfo);
    }
    if (onl_curr) *onl_curr = myonl_curr; else {
	for(i=0;i<mynumcurrs;++i) EC_M_free_onl_curr(myonl_curr[i]);
	EC_G_free(myonl_curr);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_curr(EC_M_Curr curr1, EC_M_Curr curr2)
{
    int i;

    if (!curr1 || !curr2) return 1;

    if (curr1->numcurrs != curr2->numcurrs)
	return 1;

    if (curr1->numcurrs &&
	(!curr1->cinfo || !curr2->cinfo ||
	 !curr1->onl_curr || !curr2->onl_curr))
	return 1;

    for(i=0;i<curr1->numcurrs;++i) {
	if (EC_M_cmp_cinfo(curr1->cinfo[i], curr2->cinfo[i]))
	    return 1;
    }

    for(i=0;i<curr1->numcurrs;++i) {
	if (EC_M_cmp_onl_curr(curr1->onl_curr[i], curr2->onl_curr[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_curr(EC_M_Curr curr)
{
    int i;

    if (curr) {
	for(i=0;i<curr->numcurrs;++i)
	    if (curr->cinfo)
		EC_M_free_cinfo(curr->cinfo[i]);
	if (curr->cinfo) EC_G_free(curr->cinfo);
	for(i=0;i<curr->numcurrs;++i)
	    if (curr->onl_curr)
		EC_M_free_onl_curr(curr->onl_curr[i]);
	if (curr->onl_curr) EC_G_free(curr->onl_curr);
	EC_G_free(curr);
    }
}

EC_Errno EC_M_compile_curr(EC_M_Curr curr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!curr || (curr->numcurrs && (!curr->cinfo || !curr->onl_curr)) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_CURR, msg);
    for(i=0;i<curr->numcurrs;++i) {
	if (!err) err = EC_M_compile_cinfo(curr->cinfo[i], msg);
	if (!err) err = EC_M_compile_onl_curr(curr->onl_curr[i], msg);
    }
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_curr(EC_M_Curr *curr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 numcurrs = 0;
    EC_M_Cinfo *cinfo = NULL;
    EC_M_Onl_curr *onl_curr = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_CURR, msg);
    while(!err) {
	if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
	if (!err) if (fieldtype != EC_M_FIELD_SOR ||
			rectype != EC_M_REC_CINFO) break;
	if (!err) {
	    EC_M_Cinfo *newcinfo =
		(EC_M_Cinfo *)EC_G_realloc(cinfo,
		sizeof(EC_M_Cinfo)*(numcurrs+1));
	    if (!newcinfo) {
		if (cinfo) EC_G_free(cinfo);
		err = EC_ERR_INTERNAL;
	    } else {
		cinfo = newcinfo;
	    }
	}
	if (!err) err = EC_M_decompile_cinfo(&cinfo[numcurrs], msg);
	if (!err) {
	    EC_M_Onl_curr *newonl_curr =
		(EC_M_Onl_curr *)EC_G_realloc(onl_curr,
		sizeof(EC_M_Onl_curr)*(numcurrs+1));
	    if (!newonl_curr) {
		if (onl_curr) EC_G_free(onl_curr);
		err = EC_ERR_INTERNAL;
	    } else {
		onl_curr = newonl_curr;
	    }
	}
	if (!err) err = EC_M_decompile_onl_curr(&onl_curr[numcurrs], msg);
	if (!err) ++numcurrs;
    }
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && curr) {
	*curr = EC_M_new_curr(numcurrs, cinfo, onl_curr);
	if (!*curr) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numcurrs;++i)
	if (cinfo) EC_M_free_cinfo(cinfo[i]);
    if (cinfo) EC_G_free(cinfo);
    for(i=0;i<numcurrs;++i)
	if (onl_curr) EC_M_free_onl_curr(onl_curr[i]);
    if (onl_curr) EC_G_free(onl_curr);
    return err;
}

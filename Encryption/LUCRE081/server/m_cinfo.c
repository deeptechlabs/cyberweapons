#include "lucre.h"

/*
   cinfo =
     [
       int	protocol
       int	base_val
       int	unused		; = 1
       int	currency
       int	unused		; = 1
       int	keyversion
       time	expire_time
       int	unused		; = 0
     ]
 */

EC_M_Cinfo EC_M_new_cinfo(EC_M_Protocol protocol, UInt32 base_val,
    EC_M_Currency currency, UInt32 keyversion, time_t expire_time)
{
    EC_M_Cinfo newcinfo;

    newcinfo = (EC_M_Cinfo) EC_G_malloc(sizeof(struct EC_M_Cinfo_s));
    if (!newcinfo) return newcinfo;

    newcinfo->protocol = protocol;
    /* Prevent strangeness */
    newcinfo->base_val = base_val ? base_val : 1;
    newcinfo->currency = currency;
    newcinfo->keyversion = keyversion;
    newcinfo->expire_time = expire_time;
    return newcinfo;
}

EC_M_Cinfo EC_M_clone_cinfo(EC_M_Cinfo cinfo)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Cinfo newcinfo;
    EC_M_Protocol protocol;
    UInt32 base_val;
    EC_M_Currency currency;
    UInt32 keyversion;
    time_t expire_time;
    
    err = EC_M_examine_cinfo(cinfo, &protocol, &base_val, &currency,
	&keyversion, &expire_time);
    if (!err) {
	newcinfo = EC_M_new_cinfo(protocol, base_val, currency,
	    keyversion, expire_time);
	if (newcinfo) return newcinfo;
    }

    return NULL;
}

EC_Errno EC_M_examine_cinfo(EC_M_Cinfo cinfo, EC_M_Protocol *protocol,
    UInt32 *base_val, EC_M_Currency *currency, UInt32 *keyversion,
    time_t *expire_time)
{ 
    EC_M_Protocol myprotocol;
    UInt32 mybase_val;
    EC_M_Currency mycurrency;
    UInt32 mykeyversion;
    time_t myexpire_time;

    if (!cinfo) return EC_ERR_INTERNAL;

    myprotocol = cinfo->protocol;
    mybase_val = cinfo->base_val;
    mycurrency = cinfo->currency;
    mykeyversion = cinfo->keyversion;
    myexpire_time = cinfo->expire_time;

    /* All OK */
    if (protocol) *protocol = myprotocol;
    if (base_val) *base_val = mybase_val;
    if (currency) *currency = mycurrency;
    if (keyversion) *keyversion = mykeyversion;
    if (expire_time) *expire_time = myexpire_time;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_cinfo(EC_M_Cinfo cinfo1, EC_M_Cinfo cinfo2)
{
    if (!cinfo1 || !cinfo2) return 1;

    if (cinfo1->protocol != cinfo2->protocol
     || cinfo1->base_val != cinfo2->base_val
     || cinfo1->currency != cinfo2->currency
     || cinfo1->keyversion != cinfo2->keyversion
     || cinfo1->expire_time != cinfo2->expire_time)
	return 1;

    return 0;
}

void EC_M_free_cinfo(EC_M_Cinfo cinfo)
{
    if (cinfo) {
	EC_G_free(cinfo);
    }
}

EC_Errno EC_M_compile_cinfo(EC_M_Cinfo cinfo, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!cinfo || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_CINFO, msg);
    if (!err) err = EC_M_compile_int(cinfo->protocol, msg);
    if (!err) err = EC_M_compile_int(cinfo->base_val, msg);
    if (!err) err = EC_M_compile_int(1, msg);
    if (!err) err = EC_M_compile_int(cinfo->currency, msg);
    if (!err) err = EC_M_compile_int(1, msg);
    if (!err) err = EC_M_compile_int(cinfo->keyversion, msg);
    if (!err) err = EC_M_compile_time(cinfo->expire_time, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_cinfo(EC_M_Cinfo *cinfo, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Protocol protocol;
    UInt32 base_val;
    EC_M_Currency currency;
    UInt32 keyversion;
    time_t expire_time;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_CINFO, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
    if (!err) err = EC_M_decompile_int(&base_val, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(&currency, msg);
    if (!err) err = EC_M_decompile_int(NULL, msg);
    if (!err) err = EC_M_decompile_int(&keyversion, msg);
    if (!err) err = EC_M_decompile_time(&expire_time, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && cinfo) {
	*cinfo = EC_M_new_cinfo(protocol, base_val, currency, keyversion,
	    expire_time);
	if (!*cinfo) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

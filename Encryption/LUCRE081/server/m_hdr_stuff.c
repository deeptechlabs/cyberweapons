#include "lucre.h"

/*
   hdr_stuff =
     [
       int	version_code
       time	timestamp
       int	reserved	; = 0
     ]
 */

EC_M_Hdr_stuff EC_M_new_hdr_stuff(UInt32 version, time_t timestamp)
{
    EC_M_Hdr_stuff newhdr;

    newhdr = (EC_M_Hdr_stuff) EC_G_malloc(sizeof(struct EC_M_Hdr_stuff_s));
    if (!newhdr) return newhdr;

    newhdr->version = version;
    newhdr->timestamp = timestamp;
    return newhdr;
}

EC_M_Hdr_stuff EC_M_clone_hdr_stuff(EC_M_Hdr_stuff hdr_stuff)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Hdr_stuff newhdr_stuff;
    UInt32 version;
    time_t timestamp;
    
    err = EC_M_examine_hdr_stuff(hdr_stuff, &version, &timestamp);
    if (!err) {
	newhdr_stuff = EC_M_new_hdr_stuff(version, timestamp);
	if (newhdr_stuff) return newhdr_stuff;
    }

    return NULL;
}

EC_Errno EC_M_examine_hdr_stuff(EC_M_Hdr_stuff hdr_stuff, UInt32 *version,
    time_t *timestamp)
{ 
    UInt32 myversion;
    time_t mytimestamp;

    if (!hdr_stuff) return EC_ERR_INTERNAL;

    myversion = hdr_stuff->version;
    mytimestamp = hdr_stuff->timestamp;

    /* All OK */
    if (version) *version = myversion;
    if (timestamp) *timestamp = mytimestamp;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_hdr_stuff(EC_M_Hdr_stuff hdr_stuff1, EC_M_Hdr_stuff hdr_stuff2)
{
    if (!hdr_stuff1 || !hdr_stuff2) return 1;

    if (hdr_stuff1->version != hdr_stuff2->version
     || hdr_stuff1->timestamp != hdr_stuff2->timestamp)
	return 1;

    return 0;
}

void EC_M_free_hdr_stuff(EC_M_Hdr_stuff hdr_stuff)
{
    if (hdr_stuff) {
	EC_G_free(hdr_stuff);
    }
}

EC_Errno EC_M_compile_hdr_stuff(EC_M_Hdr_stuff hdr_stuff, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!hdr_stuff || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_HDR_STUFF, msg);
    if (!err) err = EC_M_compile_int(hdr_stuff->version, msg);
    if (!err) err = EC_M_compile_time(hdr_stuff->timestamp, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_hdr_stuff(EC_M_Hdr_stuff *hdr_stuff, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 version;
    time_t timestamp;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_HDR_STUFF, msg);
    if (!err) err = EC_M_decompile_int(&version, msg);
    if (!err) err = EC_M_decompile_time(&timestamp, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && hdr_stuff) {
	*hdr_stuff = EC_M_new_hdr_stuff(version, timestamp);
	if (!*hdr_stuff) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

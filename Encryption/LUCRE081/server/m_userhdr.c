#include "lucre.h"

/*
   userhdr =
     [
       int	userID
       time	timestamp
       int	bankID
     ]
 */

EC_M_Userhdr EC_M_new_userhdr(UInt32 userID, time_t timestamp, UInt32 bankID)
{
    EC_M_Userhdr newuserhdr;

    newuserhdr = (EC_M_Userhdr) EC_G_malloc(sizeof(struct EC_M_Userhdr_s));
    if (!newuserhdr) return newuserhdr;

    newuserhdr->userID = userID;
    newuserhdr->timestamp = timestamp;
    newuserhdr->bankID = bankID;
    return newuserhdr;
}

EC_M_Userhdr EC_M_clone_userhdr(EC_M_Userhdr userhdr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Userhdr newuserhdr;
    UInt32 userID;
    time_t timestamp;
    UInt32 bankID;
    
    err = EC_M_examine_userhdr(userhdr, &userID, &timestamp, &bankID);
    if (!err) {
	newuserhdr = EC_M_new_userhdr(userID, timestamp, bankID);
	if (newuserhdr) return newuserhdr;
    }

    return NULL;
}

EC_Errno EC_M_examine_userhdr(EC_M_Userhdr userhdr, UInt32 *userID,
    time_t *timestamp, UInt32 *bankID)
{ 
    UInt32 myuserID;
    time_t mytimestamp;
    UInt32 mybankID;

    if (!userhdr) return EC_ERR_INTERNAL;

    myuserID = userhdr->userID;
    mytimestamp = userhdr->timestamp;
    mybankID = userhdr->bankID;

    /* All OK */
    if (userID) *userID = myuserID;
    if (timestamp) *timestamp = mytimestamp;
    if (bankID) *bankID = mybankID;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_userhdr(EC_M_Userhdr userhdr1, EC_M_Userhdr userhdr2)
{
    if (!userhdr1 || !userhdr2) return 1;

    if (userhdr1->userID != userhdr2->userID
     || userhdr1->timestamp != userhdr2->timestamp
     || userhdr1->bankID != userhdr2->bankID)
	return 1;

    return 0;
}

void EC_M_free_userhdr(EC_M_Userhdr userhdr)
{
    if (userhdr) {
	EC_G_free(userhdr);
    }
}

EC_Errno EC_M_compile_userhdr(EC_M_Userhdr userhdr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!userhdr || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_USERHDR, msg);
    if (!err) err = EC_M_compile_int(userhdr->userID, msg);
    if (!err) err = EC_M_compile_time(userhdr->timestamp, msg);
    if (!err) err = EC_M_compile_int(userhdr->bankID, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_userhdr(EC_M_Userhdr *userhdr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 userID;
    time_t timestamp;
    UInt32 bankID;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_USERHDR, msg);
    if (!err) err = EC_M_decompile_int(&userID, msg);
    if (!err) err = EC_M_decompile_time(&timestamp, msg);
    if (!err) err = EC_M_decompile_int(&bankID, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && userhdr) {
	*userhdr = EC_M_new_userhdr(userID, timestamp, bankID);
	if (!*userhdr) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

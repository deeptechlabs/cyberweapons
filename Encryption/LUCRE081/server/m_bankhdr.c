#include "lucre.h"

/*
   bankhdr =
     [
       int	bankID
       int	keyno
     ]
 */

EC_M_Bankhdr EC_M_new_bankhdr(UInt32 bankID, UInt32 keyno)
{
    EC_M_Bankhdr newhdr;

    newhdr = (EC_M_Bankhdr) EC_G_malloc(sizeof(struct EC_M_Bankhdr_s));
    if (!newhdr) return newhdr;

    newhdr->bankID = bankID;
    newhdr->keyno = keyno;
    return newhdr;
}

EC_M_Bankhdr EC_M_clone_bankhdr(EC_M_Bankhdr bankhdr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Bankhdr newbankhdr;
    UInt32 bankID;
    UInt32 keyno;
    
    err = EC_M_examine_bankhdr(bankhdr, &bankID, &keyno);
    if (!err) {
	newbankhdr = EC_M_new_bankhdr(bankID, keyno);
	if (newbankhdr) return newbankhdr;
    }

    return NULL;
}

EC_Errno EC_M_examine_bankhdr(EC_M_Bankhdr bankhdr, UInt32 *bankID,
    UInt32 *keyno)
{ 
    UInt32 mybankID;
    UInt32 mykeyno;

    if (!bankhdr) return EC_ERR_INTERNAL;

    mybankID = bankhdr->bankID;
    mykeyno = bankhdr->keyno;

    /* All OK */
    if (bankID) *bankID = mybankID;
    if (keyno) *keyno = mykeyno;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_bankhdr(EC_M_Bankhdr bankhdr1, EC_M_Bankhdr bankhdr2)
{
    if (!bankhdr1 || !bankhdr2) return 1;

    if (bankhdr1->bankID != bankhdr2->bankID
     || bankhdr1->keyno != bankhdr2->keyno)
	return 1;

    return 0;
}

void EC_M_free_bankhdr(EC_M_Bankhdr bankhdr)
{
    if (bankhdr) {
	EC_G_free(bankhdr);
    }
}

EC_Errno EC_M_compile_bankhdr(EC_M_Bankhdr bankhdr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!bankhdr || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_BANKHDR, msg);
    if (!err) err = EC_M_compile_int(bankhdr->bankID, msg);
    if (!err) err = EC_M_compile_int(bankhdr->keyno, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_bankhdr(EC_M_Bankhdr *bankhdr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 bankID;
    UInt32 keyno;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_BANKHDR, msg);
    if (!err) err = EC_M_decompile_int(&bankID, msg);
    if (!err) err = EC_M_decompile_int(&keyno, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && bankhdr) {
	*bankhdr = EC_M_new_bankhdr(bankID, keyno);
	if (!*bankhdr) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

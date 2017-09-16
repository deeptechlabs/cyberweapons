#include "lucre.h"

/*
   USERREC =
     [
       int  userID
       userkey
       int  bankID
       int  currency
       string ??
       string username
     ]
 */

EC_M_Userrec EC_M_new_userrec(UInt32 userID, EC_M_Userkey userkey,
    UInt32 bankID, EC_M_Currency currency, char *username)
{
    EC_M_Userrec newuserrec;

    newuserrec =
	(EC_M_Userrec) EC_G_malloc(sizeof(struct EC_M_Userrec_s));
    if (!newuserrec) return newuserrec;

    newuserrec->userID = userID;
    newuserrec->userkey = userkey;
    newuserrec->bankID = bankID;
    newuserrec->currency = currency;
    newuserrec->username = username;
    return newuserrec;
}

EC_M_Userrec EC_M_clone_userrec(EC_M_Userrec userrec)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Userrec newuserrec;
    UInt32 userID;
    EC_M_Userkey userkey = NULL;
    UInt32 bankID;
    EC_M_Currency currency;
    char *username = NULL;

    err = EC_M_examine_userrec(userrec, &userID, &userkey, &bankID,
	&currency, &username);
    if (!err) {
	newuserrec = EC_M_new_userrec(userID, userkey, bankID,
	    currency, username);
	if (newuserrec) return newuserrec;
    }

    EC_M_free_userkey(userkey);
    if (username) EC_G_free(username);
    return NULL;
}

EC_Errno EC_M_examine_userrec(EC_M_Userrec userrec, UInt32 *userID,
    EC_M_Userkey *userkey, UInt32 *bankID, EC_M_Currency *currency,
    char **username)
{ 
    UInt32 myuserID;
    EC_M_Userkey myuserkey = NULL;
    UInt32 mybankID;
    EC_M_Currency mycurrency;
    char *myusername = NULL;

    if (!userrec) return EC_ERR_INTERNAL;

    myuserID = userrec->userID;
    myuserkey = EC_M_clone_userkey(userrec->userkey);
    mybankID = userrec->bankID;
    mycurrency = userrec->currency;
    myusername = EC_G_strdup(userrec->username);

    if (!myuserkey || !myusername) {
	EC_M_free_userkey(myuserkey);
	if (myusername) EC_G_free(myusername);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (userID) *userID = myuserID;
    if (userkey) *userkey = myuserkey; else EC_M_free_userkey(myuserkey);
    if (bankID) *bankID = mybankID;
    if (currency) *currency = mycurrency;
    if (username) *username = myusername; else EC_G_free(myusername);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_userrec(EC_M_Userrec userrec1, EC_M_Userrec userrec2)
{
    if (!userrec1 || !userrec2) return 1;

    if (userrec1->userID != userrec2->userID
     || EC_M_cmp_userkey(userrec1->userkey, userrec2->userkey)
     || userrec1->bankID != userrec2->bankID
     || userrec1->currency != userrec2->currency
     || strcmp(userrec1->username, userrec2->username))
	return 1;

    return 0;
}

void EC_M_free_userrec(EC_M_Userrec userrec)
{
    if (userrec) {
	EC_M_free_userkey(userrec->userkey);
	if (userrec->username) EC_G_free(userrec->username);
	EC_G_free(userrec);
    }
}

EC_Errno EC_M_compile_userrec(EC_M_Userrec userrec, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!userrec || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_USERREC, msg);
    if (!err) err = EC_M_compile_int(userrec->userID, msg);
    if (!err) err = EC_M_compile_userkey(userrec->userkey, msg);
    if (!err) err = EC_M_compile_int(userrec->bankID, msg);
    if (!err) err = EC_M_compile_int(userrec->currency, msg);
    if (!err) err = EC_M_compile_string(NULL, msg);
    if (!err) err = EC_M_compile_string(userrec->username, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_userrec(EC_M_Userrec *userrec, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 userID;
    EC_M_Userkey userkey = NULL;
    UInt32 bankID;
    EC_M_Currency currency;
    char *username = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_USERREC, msg);
    if (!err) err = EC_M_decompile_int(&userID, msg);
    if (!err) err = EC_M_decompile_userkey(&userkey, msg);
    if (!err) err = EC_M_decompile_int(&bankID, msg);
    if (!err) err = EC_M_decompile_int(&currency, msg);
    if (!err) err = EC_M_decompile_string(NULL, msg);
    if (!err) err = EC_M_decompile_string(&username, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && userrec) {
	*userrec = EC_M_new_userrec(userID, userkey, bankID,
	    currency, username);
	if (!*userrec) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_userkey(userkey);
    if (username) EC_G_free(username);
    return err;
}

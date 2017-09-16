#include "lucre.h"

/*
   userinfo =
     [
        string  accID
        string  name
        string  email
        int     currency
     ]
 */

EC_M_Userinfo EC_M_new_userinfo(char *accID, char *name, char *email,
    EC_M_Currency currency)
{
    EC_M_Userinfo newuserinfo;

    if (!accID || !name || !email) return NULL;
    newuserinfo = (EC_M_Userinfo) EC_G_malloc(sizeof(struct EC_M_Userinfo_s));
    if (!newuserinfo) return newuserinfo;

    newuserinfo->accID = accID;
    newuserinfo->name = name;
    newuserinfo->email = email;
    newuserinfo->currency = currency;
    return newuserinfo;
}

EC_M_Userinfo EC_M_clone_userinfo(EC_M_Userinfo userinfo)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Userinfo newuserinfo;
    char *accID = NULL;
    char *name = NULL;
    char *email = NULL;
    EC_M_Currency currency;
    
    err = EC_M_examine_userinfo(userinfo, &accID, &name, &email, &currency);
    if (!err) {
	newuserinfo = EC_M_new_userinfo(accID, name, email, currency);
	if (newuserinfo) return newuserinfo;
    }

    if (accID) EC_G_free(accID);
    if (name) EC_G_free(name);
    if (email) EC_G_free(email);
    return NULL;
}

EC_Errno EC_M_examine_userinfo(EC_M_Userinfo userinfo, char **accID,
    char **name, char **email, EC_M_Currency *currency)
{ 
    char *myaccID;
    char *myname;
    char *myemail;
    EC_M_Currency mycurrency;

    if (!userinfo) return EC_ERR_INTERNAL;

    myaccID = EC_G_strdup(userinfo->accID);
    myname = EC_G_strdup(userinfo->name);
    myemail = EC_G_strdup(userinfo->email);
    mycurrency = userinfo->currency;

    if (!myaccID || !myname || !myemail) {
	/* Didn't copy properly; abort */
	if (myaccID) EC_G_free(myaccID);
	if (myname) EC_G_free(myname);
	if (myemail) EC_G_free(myemail);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (accID) *accID = myaccID; else EC_G_free(myaccID);
    if (name) *name = myname; else EC_G_free(myname);
    if (email) *email = myemail; else EC_G_free(myemail);
    if (currency) *currency = mycurrency;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_userinfo(EC_M_Userinfo userinfo1, EC_M_Userinfo userinfo2)
{
    if (!userinfo1 || !userinfo2) return 1;

    if (strcmp(userinfo1->accID, userinfo2->accID)
     || strcmp(userinfo1->name, userinfo2->name)
     || strcmp(userinfo1->email, userinfo2->email)
     || userinfo1->currency != userinfo2->currency)
	return 1;

    return 0;
}

void EC_M_free_userinfo(EC_M_Userinfo userinfo)
{
    if (userinfo) {
	if (userinfo->accID) EC_G_free(userinfo->accID);
	if (userinfo->name) EC_G_free(userinfo->name);
	if (userinfo->email) EC_G_free(userinfo->email);
	EC_G_free(userinfo);
    }
}

EC_Errno EC_M_compile_userinfo(EC_M_Userinfo userinfo, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!userinfo || !userinfo->accID || !userinfo->name || !userinfo->email
	|| !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_USERINFO, msg);
    if (!err) err = EC_M_compile_string(userinfo->accID, msg);
    if (!err) err = EC_M_compile_string(userinfo->name, msg);
    if (!err) err = EC_M_compile_string(userinfo->email, msg);
    if (!err) err = EC_M_compile_int(userinfo->currency, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_userinfo(EC_M_Userinfo *userinfo, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    char *accID = NULL;
    char *name = NULL;
    char *email = NULL;
    EC_M_Currency currency;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_USERINFO, msg);
    if (!err) err = EC_M_decompile_string(&accID, msg);
    if (!err) err = EC_M_decompile_string(&name, msg);
    if (!err) err = EC_M_decompile_string(&email, msg);
    if (!err) err = EC_M_decompile_int(&currency, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && userinfo) {
	*userinfo = EC_M_new_userinfo(accID, name, email, currency);
	if (!*userinfo) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    if (accID) EC_G_free(accID);
    if (name) EC_G_free(name);
    if (email) EC_G_free(email);
    return err;
}

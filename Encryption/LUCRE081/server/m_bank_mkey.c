#include "lucre.h"

/*
   BANK_MKEY =
     [
       int	bankID
       int	keynumber
       time	timestamp
       string	bankname
       string	bankemail
       int	numaddrs
       string	bankaddr[numaddrs]
       int	withdrawindex
       int	bankport
       MPI	bank_n
       MPI	bank_e
       int	maxcoins
       int	unused
     ]
 */

EC_M_Bank_mkey EC_M_new_bank_mkey(UInt32 bankID, UInt32 keynumber,
    time_t timestamp, char *bankname, char *bankemail, UInt32 numaddrs,
    char **bankaddr, UInt32 withdrawindex, UInt32 bankport,
    BIGNUM *bank_n, BIGNUM *bank_e, UInt32 maxcoins)
{
    EC_M_Bank_mkey newbank_mkey;

    if (!bankname || !bankemail || !bankaddr || !bank_n || !bank_e)
	return NULL;
    newbank_mkey =
	(EC_M_Bank_mkey) EC_G_malloc(sizeof(struct EC_M_Bank_mkey_s));
    if (!newbank_mkey) return newbank_mkey;

    newbank_mkey->bankID = bankID;
    newbank_mkey->keynumber = keynumber;
    newbank_mkey->timestamp = timestamp;
    newbank_mkey->bankname = bankname;
    newbank_mkey->bankemail = bankemail;
    newbank_mkey->numaddrs = numaddrs;
    newbank_mkey->bankaddr = bankaddr;
    newbank_mkey->withdrawindex = withdrawindex;
    newbank_mkey->bankport = bankport;
    newbank_mkey->bank_n = bank_n;
    newbank_mkey->bank_e = bank_e;
    newbank_mkey->maxcoins = maxcoins;

    return newbank_mkey;
}

EC_M_Bank_mkey EC_M_clone_bank_mkey(EC_M_Bank_mkey bank_mkey)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Bank_mkey newbank_mkey;
    UInt32 bankID;
    UInt32 keynumber;
    time_t timestamp;
    char *bankname = NULL;
    char *bankemail = NULL;
    UInt32 numaddrs = 0;
    char **bankaddr = NULL;
    UInt32 withdrawindex;
    UInt32 bankport;
    BIGNUM *bank_n = NULL;
    BIGNUM *bank_e = NULL;
    UInt32 maxcoins;

    int i;
    
    err = EC_M_examine_bank_mkey(bank_mkey, &bankID, &keynumber, &timestamp,
	    &bankname, &bankemail, &numaddrs, &bankaddr, &withdrawindex,
	    &bankport, &bank_n, &bank_e, &maxcoins);
    if (!err) {
	newbank_mkey = EC_M_new_bank_mkey(bankID, keynumber, timestamp,
	    bankname, bankemail, numaddrs, bankaddr, withdrawindex,
	    bankport, bank_n, bank_e, maxcoins);
	if (newbank_mkey) return newbank_mkey;
    }

    if (bankname) EC_G_free(bankname);
    if (bankemail) EC_G_free(bankemail);
    for(i=0;i<numaddrs;++i)
	if (bankaddr && bankaddr[i]) EC_G_free(bankaddr[i]);
    if (bankaddr) EC_G_free(bankaddr);
    EC_M_free_MPI(bank_n);
    EC_M_free_MPI(bank_e);

    return NULL;
}

EC_Errno EC_M_examine_bank_mkey(EC_M_Bank_mkey bank_mkey, 
    UInt32 *bankID, UInt32 *keynumber,
    time_t *timestamp, char **bankname, char **bankemail, UInt32 *numaddrs,
    char ***bankaddr, UInt32 *withdrawindex, UInt32 *bankport,
    BIGNUM **bank_n, BIGNUM **bank_e, UInt32 *maxcoins)
{ 
    UInt32 mybankID;
    UInt32 mykeynumber;
    time_t mytimestamp;
    char *mybankname;
    char *mybankemail;
    UInt32 mynumaddrs;
    char **mybankaddr;
    UInt32 mywithdrawindex;
    UInt32 mybankport;
    BIGNUM *mybank_n;
    BIGNUM *mybank_e;
    UInt32 mymaxcoins;

    int i;
    int seenbad = 0;

    if (!bank_mkey) return EC_ERR_INTERNAL;

    mybankID = bank_mkey->bankID;
    mykeynumber = bank_mkey->keynumber;
    mytimestamp = bank_mkey->timestamp;
    mybankname = EC_G_strdup(bank_mkey->bankname);
    mybankemail = EC_G_strdup(bank_mkey->bankemail);
    mynumaddrs = bank_mkey->numaddrs;
    mybankaddr = (char **)EC_G_malloc(sizeof(char *)*mynumaddrs);
    if (mybankaddr) for(i=0;i<mynumaddrs;++i) {
	mybankaddr[i] = EC_G_strdup(bank_mkey->bankaddr[i]);
	if (!mybankaddr[i]) seenbad = 1;
    }
    mywithdrawindex = bank_mkey->withdrawindex;
    mybankport = bank_mkey->bankport;
    mybank_n = EC_M_clone_MPI(bank_mkey->bank_n);
    mybank_e = EC_M_clone_MPI(bank_mkey->bank_e);
    mymaxcoins = bank_mkey->maxcoins;

    if (!mybankname || !mybankemail || !mybankaddr || !mybank_n || !mybank_e
	    || seenbad) {
	/* Didn't copy properly; abort */
	if (mybankname) EC_G_free(mybankname);
	if (mybankemail) EC_G_free(mybankemail);
	for(i=0;i<mynumaddrs;++i)
	    if (mybankaddr && mybankaddr[i]) EC_G_free(mybankaddr[i]);
	if (mybankaddr) EC_G_free(mybankaddr);
	EC_M_free_MPI(mybank_n);
	EC_M_free_MPI(mybank_e);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (bankID) *bankID = mybankID;
    if (keynumber) *keynumber = mykeynumber;
    if (timestamp) *timestamp = mytimestamp;
    if (bankname) *bankname = mybankname; else EC_G_free(mybankname);
    if (bankemail) *bankemail = mybankemail; else EC_G_free(mybankemail);
    if (numaddrs) *numaddrs = mynumaddrs;
    if (bankaddr) *bankaddr = mybankaddr; else {
	for(i=0;i<mynumaddrs;++i) EC_G_free(mybankaddr[i]);
	EC_G_free(mybankaddr);
    }
    if (withdrawindex) *withdrawindex = mywithdrawindex;
    if (bankport) *bankport = mybankport;
    if (bank_n) *bank_n = mybank_n; else EC_M_free_MPI(mybank_n);
    if (bank_e) *bank_e = mybank_e; else EC_M_free_MPI(mybank_e);
    if (maxcoins) *maxcoins = mymaxcoins;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_bank_mkey(EC_M_Bank_mkey bank_mkey1, EC_M_Bank_mkey bank_mkey2)
{
    int i;

    if (!bank_mkey1 || !bank_mkey2) return 1;

    if (bank_mkey1->bankID != bank_mkey2->bankID ||
	bank_mkey1->keynumber != bank_mkey2->keynumber ||
	bank_mkey1->timestamp != bank_mkey2->timestamp ||
	strcmp(bank_mkey1->bankname, bank_mkey2->bankname) ||
	strcmp(bank_mkey1->bankemail, bank_mkey2->bankemail) ||
	bank_mkey1->numaddrs != bank_mkey2->numaddrs ||
	bank_mkey1->withdrawindex != bank_mkey2->withdrawindex ||
	bank_mkey1->bankport != bank_mkey2->bankport ||
	EC_M_cmp_MPI(bank_mkey1->bank_n, bank_mkey2->bank_n) ||
	EC_M_cmp_MPI(bank_mkey1->bank_e, bank_mkey2->bank_e) ||
	bank_mkey1->maxcoins != bank_mkey2->maxcoins)
	return 1;

    if (bank_mkey1->numaddrs &&
	(!bank_mkey1->bankaddr || !bank_mkey2->bankaddr))
	return 1;

    for(i=0;i<bank_mkey1->numaddrs;++i)
	if (strcmp(bank_mkey1->bankaddr[i], bank_mkey2->bankaddr[i]))
	    return 1;

    return 0;
}

void EC_M_free_bank_mkey(EC_M_Bank_mkey bank_mkey)
{
    int i;

    if (bank_mkey) {
	if (bank_mkey->bankname) EC_G_free(bank_mkey->bankname);
	if (bank_mkey->bankemail) EC_G_free(bank_mkey->bankemail);
	for(i=0;i<bank_mkey->numaddrs;++i)
	    if (bank_mkey->bankaddr && bank_mkey->bankaddr[i])
		EC_G_free(bank_mkey->bankaddr[i]);
	if (bank_mkey->bankaddr) EC_G_free(bank_mkey->bankaddr);
	EC_M_free_MPI(bank_mkey->bank_n);
	EC_M_free_MPI(bank_mkey->bank_e);
	EC_G_free(bank_mkey);
    }
}

EC_Errno EC_M_compile_bank_mkey(EC_M_Bank_mkey bank_mkey, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    int i;

    if (!bank_mkey || !bank_mkey->bankname || !bank_mkey->bankemail ||
	(bank_mkey->numaddrs && !bank_mkey->bankaddr) ||
	!bank_mkey->bank_n || !bank_mkey->bank_e ||
	!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_BANK_MKEY, msg);
    if (!err) err = EC_M_compile_int(bank_mkey->bankID, msg);
    if (!err) err = EC_M_compile_int(bank_mkey->keynumber, msg);
    if (!err) err = EC_M_compile_time(bank_mkey->timestamp, msg);
    if (!err) err = EC_M_compile_string(bank_mkey->bankname, msg);
    if (!err) err = EC_M_compile_string(bank_mkey->bankemail, msg);
    if (!err) err = EC_M_compile_int(bank_mkey->numaddrs, msg);
    for (i=0;i<bank_mkey->numaddrs;++i)
	if (!err) err = EC_M_compile_string(bank_mkey->bankaddr[i], msg);
    if (!err) err = EC_M_compile_int(bank_mkey->withdrawindex, msg);
    if (!err) err = EC_M_compile_int(bank_mkey->bankport, msg);
    if (!err) err = EC_M_compile_MPI(bank_mkey->bank_n, msg);
    if (!err) err = EC_M_compile_MPI(bank_mkey->bank_e, msg);
    if (!err) err = EC_M_compile_int(bank_mkey->maxcoins, msg);
    if (!err) err = EC_M_compile_int(0, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_bank_mkey(EC_M_Bank_mkey *bank_mkey, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 bankID;
    UInt32 keynumber;
    time_t timestamp;
    char *bankname = NULL;
    char *bankemail = NULL;
    UInt32 numaddrs = 0;
    char **bankaddr = NULL;
    UInt32 withdrawindex;
    UInt32 bankport;
    BIGNUM *bank_n = NULL;
    BIGNUM *bank_e = NULL;
    UInt32 maxcoins;

    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_BANK_MKEY, msg);
    if (!err) err = EC_M_decompile_int(&bankID, msg);
    if (!err) err = EC_M_decompile_int(&keynumber, msg);
    if (!err) err = EC_M_decompile_time(&timestamp, msg);
    if (!err) err = EC_M_decompile_string(&bankname, msg);
    if (!err) err = EC_M_decompile_string(&bankemail, msg);
    if (!err) err = EC_M_decompile_int(&numaddrs, msg);
    if (!err) {
	bankaddr = (char **)EC_G_malloc(sizeof(char *)*numaddrs);
	if (!bankaddr) err = EC_ERR_INTERNAL;
    }
    for (i=0;i<numaddrs;++i)
	if (!err) err = EC_M_decompile_string(&bankaddr[i], msg);
    if (!err) err = EC_M_decompile_int(&withdrawindex, msg);
    if (!err) err = EC_M_decompile_int(&bankport, msg);
    if (!err) err = EC_M_decompile_MPI(&bank_n, msg);
    if (!err) err = EC_M_decompile_MPI(&bank_e, msg);
    if (!err) err = EC_M_decompile_int(&maxcoins, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && bank_mkey) {
	*bank_mkey = EC_M_new_bank_mkey(bankID, keynumber,
			    timestamp, bankname, bankemail, numaddrs,
			    bankaddr, withdrawindex, bankport, bank_n,
			    bank_e, maxcoins);
	if (!*bank_mkey) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    if (bankname) EC_G_free(bankname);
    if (bankemail) EC_G_free(bankemail);
    for(i=0;i<numaddrs;++i)
	if (bankaddr && bankaddr[i]) EC_G_free(bankaddr[i]);
    if (bankaddr) EC_G_free(bankaddr);
    EC_M_free_MPI(bank_n);
    EC_M_free_MPI(bank_e);
    return err;
}

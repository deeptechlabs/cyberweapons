#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include "lucre.h"

/* These routines are used to create databases in the wallet, including
   those for received payments and coins.  Every attempt should be made
   to keep these hash tables _portable_ (e.g. watch byte-ordering!).
   Rightnow, we just use Berkeley DB.  We can't use dbm, because it puts
   a limit (1K) on key/data sizes.  Keys and data are EC_M_Msg values. */

/* Open a database in a given wallet.  dbname is the name of the database.
   flags is either O_RDONLY or O_RDWR.  The calling routine should get
   an appropriate lock on the wallet before calling this.  Returns NULL
   on error. */
EC_W_Db EC_W_db_open(EC_W_Wallet wallet, char *dbname, int flags)
{
    char *fullname;
#if 0
    HASHINFO hinfo;
#endif
    EC_W_Db db;

    if (!wallet || !dbname || (flags != O_RDONLY && flags != O_RDWR))
	return NULL;

    /* Construct the filename for the database */
    fullname = EC_W_wallet_mkfname(wallet->name, dbname, "");
    if (!fullname) return NULL;

#if 0
    /* Fill in the HASHINFO in a portable way */

    /* Whoa!  If we set the lorder explicitly below, some things get written
       big-endian and some get written little-endian.  Bad.  Commenting
       this out makes everything get written in host order (according
       to the documentation).  Machines with the other order are supposed
       to be able to transparently access these dbs, but I have a feeling
       they'll run into the same problem... */

    hinfo.bsize = 0;
    hinfo.ffactor = 0;
    hinfo.nelem = 0;
    hinfo.cachesize = 0;
    hinfo.hash = NULL;
    hinfo.lorder = 4321;    /* big-endian */
#endif

    /* Add O_CREAT if opening for writing */
    if (flags == O_RDWR) flags |= O_CREAT;

    db = dbopen(fullname, flags, S_IRUSR|S_IWUSR, DB_HASH, NULL);
    EC_G_free(fullname);

    return db;
}

Int32 EC_W_db_close(EC_W_Db db)
{
    int res;

    if (!db) { errno = EFAULT; return -1; }

    res = db->close(db);
    return (Int32)res;
}

Int32 EC_W_db_del(EC_W_Db db, EC_M_Msg key)
{
    DBT dbt;
    int res;

    if (!db || !key) { errno = EFAULT; return -1; }

    dbt.data = key->data+key->begin;
    dbt.size = key->end-key->begin;

    res = db->del(db, &dbt, 0);
    return (Int32)res;
}

Int32 EC_W_db_get(EC_W_Db db, EC_M_Msg key, EC_M_Msg *data)
{
    DBT keydbt, datadbt;
    int res;
    EC_Errno err;
    EC_M_Msg copydata;

    if (!db || !key) { errno = EFAULT; return -1; }

    keydbt.data = key->data+key->begin;
    keydbt.size = key->end-key->begin;

    res = db->get(db, &keydbt, &datadbt, 0);
    if (!res && data) {
	/* Success; copy the data */
	copydata = EC_M_new_msg();
	if (!copydata) { errno = ENOMEM; return -1; }

	err = EC_M_append_msg(datadbt.data, datadbt.size, copydata);
	if (err) {
	    EC_M_free_msg(copydata);
	    errno = ENOMEM;
	    return -1;
	}

	*data = copydata;
    }

    return (Int32)res;
}

Int32 EC_W_db_put(EC_W_Db db, EC_M_Msg key, EC_M_Msg data)
{
    DBT keydbt, datadbt;
    int res;

    if (!db || !key || !data) { errno = EFAULT; return -1; }

    keydbt.data = key->data+key->begin;
    keydbt.size = key->end-key->begin;
    datadbt.data = data->data+data->begin;
    datadbt.size = data->end-data->begin;

    res = db->put(db, &keydbt, &datadbt, 0);
    return (Int32)res;
}

Int32 EC_W_db_sync(EC_W_Db db)
{
    int res;

    if (!db) { errno = EFAULT; return -1; }

    res = db->sync(db, 0);
    return (Int32)res;
}

Int32 EC_W_db_seq(EC_W_Db db, EC_M_Msg *key, EC_M_Msg *data)
{
    DBT keydbt, datadbt;
    int res;
    EC_Errno err;
    EC_M_Msg copykey = NULL;
    EC_M_Msg copydata = NULL;

    if (!db) { errno = EFAULT; return -1; }

    res = db->seq(db, &keydbt, &datadbt, R_NEXT);
    if (!res && key) {
	/* Success; copy the key */
	copykey = EC_M_new_msg();
	if (!copykey) { errno = ENOMEM; return -1; }

	err = EC_M_append_msg(keydbt.data, keydbt.size, copykey);
	if (err) {
	    EC_M_free_msg(copykey);
	    errno = ENOMEM;
	    return -1;
	}
    }
    if (!res && data) {
	/* copy the data */
	copydata = EC_M_new_msg();
	if (!copydata) {
	    EC_M_free_msg(copykey);
	    errno = ENOMEM;
	    return -1;
	}

	err = EC_M_append_msg(datadbt.data, datadbt.size, copydata);
	if (err) {
	    EC_M_free_msg(copydata);
	    EC_M_free_msg(copykey);
	    errno = ENOMEM;
	    return -1;
	}
    }

    if (!res && key) *key = copykey;
    if (!res && data) *data = copydata;

    return (Int32)res;
}

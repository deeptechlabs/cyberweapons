#include "lucre.h"

/*
   STATEMENT =
     [
       int	balance
     ]
 */

EC_M_Statement EC_M_new_statement(UInt32 balance)
{
    EC_M_Statement newstatement;

    newstatement =
	(EC_M_Statement) EC_G_malloc(sizeof(struct EC_M_Statement_s));
    if (!newstatement) return newstatement;

    newstatement->balance = balance;
    return newstatement;
}

EC_M_Statement EC_M_clone_statement(EC_M_Statement statement)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Statement newstatement;
    UInt32 balance;
    
    err = EC_M_examine_statement(statement, &balance);
    if (!err) {
	newstatement = EC_M_new_statement(balance);
	if (newstatement) return newstatement;
    }

    return NULL;
}

EC_Errno EC_M_examine_statement(EC_M_Statement statement, UInt32 *balance)
{ 
    UInt32 mybalance;

    if (!statement) return EC_ERR_INTERNAL;

    mybalance = statement->balance;

    /* All OK */
    if (balance) *balance = mybalance;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_statement(EC_M_Statement statement1, EC_M_Statement statement2)
{
    if (!statement1 || !statement2) return 1;

    if (statement1->balance != statement2->balance)
	return 1;

    return 0;
}

void EC_M_free_statement(EC_M_Statement statement)
{
    if (statement) {
	EC_G_free(statement);
    }
}

EC_Errno EC_M_compile_statement(EC_M_Statement statement, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!statement || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_STATEMENT, msg);
    if (!err) err = EC_M_compile_int(statement->balance, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_statement(EC_M_Statement *statement, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 balance;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_STATEMENT, msg);
    if (!err) err = EC_M_decompile_int(&balance, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && statement) {
	*statement = EC_M_new_statement(balance);
	if (!*statement) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    return err;
}

/*********************************************************************
*                                                                    *
* ecash.h                                                            *
*                                                                    *
* Version history:                                                   *
*  960123 -   Ian Goldberg <iang@cs.berkeley.edu>                    *
*  960129 -   Felix Croes <felix@digicash.com>                       *
*  960327 -   Bryce Wilcox <bryce@digicash.com>                      *
*             Felix Croes <felix@digicash.com>                       *
*             Marcel van der Peijl <bigmac@digicash.com>             *
*             Branko Lankester <branko@digicash.com>                 *
*             Niels Ferguson <niels@digicash.com>                    *
*                                                                    *
*                                                                    *
* Copyright (c) 1996 DigiCash                                        *
*                                                                    *
* "DigiCash" and "Ecash" are trademarks.                             *
*                                                                    *
* This file is published for informational purposes only.  DigiCash  *
* makes no claims about its suitability for any particular purpose.  *
*                                                                    *
*********************************************************************/


#ifndef EC_INCL_ECASH_H
#define EC_INCL_ECASH_H

#include <stddef.h>
#include "ecashdef.h"


/* Conventions:
 *
 *
 *     Names
 *
 * All global symbols and data types are prefixed with "EC_" to 
 * prevent namespace conflicts.
 *
 * 
 * For functions:   EC_class_function_name
 * For data types:  EC_DataTypeName
 * For constants:   EC_CONSTANT_NAME
 * For variables:   var_name
 *            or:   var_name_ypn
 *             
 * Each function name includes the name of a "class" to which that 
 * function belongs.  Functions which have no class use the name 
 * "main" for their class name.
 * 
 * Variable names have special conventions.  (In this API variable
 * names are only found as parameter names in function 
 * declarations.)  If a parameter is a pointer and it is going to 
 * be the caller's responsibility to free the pointer afterward, then 
 * "_ypn" ("your pointer now") is appended.
 *
 * In addition, pointer variables have "_ptr" in their name and
 * NULL-terminated char * variables have "_str" in their name.
 *
 *
 *    Parameters
 *
 * Functions which belong to a class always have as their first
 * parameter a pointer to an instance of that class.
 *
 * Pointer parameters which are used to pass data out of the function
 * always occur after other parameters.
 *
 * On some platforms functions which are exported from the ecashlib
 * will need a keyword in the declaration (e.g. "far", "loadds", 
 * "pascal").  To handle this, each function declared in the API 
 * header files will be prefixed with a macro "EXPORT" which will be
 * #define'd to the appropriate keywords for that platform.  Each
 * application function that is to be called by the ecashlib must be
 * pre-fixed by the macro "CALLBACK" which will be similarly
 * #define'd.
 */


/* What version of the API is this?  The major number is the
 * version of the API.  The minor number represents a revision
 * of the API which is not a version change.
 * Format: major * 0x0100 + minor
 */
#define EC_API_VERSION 0x0100




/* The logging levels used by the log callback function. */
typedef enum 
{
   EC_LOGLEVEL_DEBUG = 0, /* debugging info */
   EC_LOGLEVEL_INFO = 1, /* general information */
   EC_LOGLEVEL_NOTICE = 2, /* notices */
   EC_LOGLEVEL_WARNING = 3, /* warnings */
   EC_LOGLEVEL_ERROR = 4 /* errors */
} EC_LogLevel;



   /* EC_Errno */

/* Every function except for the "Get data" functions returns
 * an EC_Errno.  Also each action handler has an EC_Errno which is a 
 * part of its state, and is accessible via EC_acth_get_errno().
 *
 *
 *   EC_ERR_NONE
 * No error.
 *
 *   EC_ERR_ACTION_ABORTED
 * A complex action was aborted via a call to its action handler's 
 * "EC_acth_abort()" function.
 *
 *   EC_ERR_ACTION_REJECTED
 * A complex action was rejected by the mint or by the other party to 
 * the transaction.  It is likely that the rejecting party sent a
 * communication describing the reason for rejection.  See 
 * EC_acth_get_communication().
 *
 *   EC_ERR_BAD_VALUE
 * A value was encountered which was of the proper form, but which did
 * not cause the desired result.  This is typically bad user input.  
 * This error is never fatal.
 *
 *   EC_ERR_ILLEGAL_OPERATION
 * A condition was encountered which should never occur in a bug-free
 * application.  Typically this is caused by the application passing 
 * an illegal value to the ecashlib.
 *
 *   EC_ERR_ACTH_MANAGEMENT
 * An ecashlib action handler was mis-used, e.g. calling 
 * EC_acth_set_msg() when the action handler does not require any 
 * message.  These errors are rarely fatal.
 *
 *   EC_ERR_INTERNAL
 * An unknown error has occurred within the ecashlib.  This could be 
 * caused by a particularly destructive error on the part of the 
 * application, or it could be caused by an error on the part of the 
 * ecashlib.  These errors may be fatal.
 */


typedef enum
{
   EC_ERR_NONE = 0,
   EC_ERR_ACTION_ABORTED = 1,
   EC_ERR_ACTION_REJECTED = 2,
   EC_ERR_BAD_VALUE = 3,
   EC_ERR_ILLEGAL_OPERATION = 4,
   EC_ERR_ACTH_MANAGEMENT = 5,
   EC_ERR_INTERNAL = 6 
} EC_Errno;



   /* EC_Record, EC_PaymentRecord and EC_Booking */

/* The ecashlib keeps a list of records.  There are two types of 
 * records: coin payment records, and bookings-- or records of things
 * that happened to the account.
 */


typedef struct EC_RecordList_s EC_RecordList;

typedef struct EC_Record_s EC_Record;

typedef struct EC_Booking_s EC_Booking;

typedef struct EC_PaymentRecord_s EC_PaymentRecord;


   /* EC_ActionHandler */

/* An EC_ActionHandler is responsible for managing the interaction
 * between the application and the ecashlib during a "complex 
 * action".
 *
 * There is exactly one EC_ActionHandler per complex action.  It is
 * created in response to the "EC_acc_begin" call that initiated the
 * complex action.
 */


typedef struct EC_ActionHandler_s EC_ActionHandler;



   /* EC_Msg */

/* An EC_Msg contains information that is to be passed from client
 * to client or client to server or server to client.  Usually
 * the contents of an EC_Msg are not important to the application--
 * it is just a chunk of data with a length.
 */

typedef struct EC_Msg_s EC_Msg;



   /* Int, Short, Long, Int32, Int16, Byte */

/* ecashdef.h defines the following:
 * 
 * Int -- a primitive datatype which is at least as long as a Short
 *   and at most as long as a Long.
 * UInt -- same as above, but unsigned.
 * Short -- a primitive datatype which is at least 16 bits.
 * UShort -- same as above, but unsigned.
 * Long -- a primitive datatype which is at least 32 bits and is at
 *   least as long as a Short.
 * ULong -- same as above, but unsigned.
 * Int32 -- a primitive datatype which is exactly 32 bits long.
 * UInt32 -- same as above but unsigned.
 * Int16 -- a primitive datatype which is exactly 16 bits long.
 * UInt16 -- same as above but unsigned.
 * Byte -- a primitive datatype which is exactly 8 bits long and
 *   unsigned.
 */




   /* EC_AccountID */

/* An EC_AccountID is a NULL-terminated string which uniquely
 * identifies an account at an ecash mint.
 */


typedef char *EC_AccountID;

EC_Errno EC_accID_free(EC_AccountID *account_ID_ptr);



   /* EC_MintID */

/* An EC_MintID is an unsigned 32-bit int which uniquely
 * identifies an ecash mint.  The list of mint ID's already taken is
 * maintained by DigiCash.
 */


typedef UInt32 EC_MintID;



   /* EC_Address */

/* An EC_Address contains all the information necessary for the 
 * application to deliver a message to another ecash application.  
 * The contents and the format are invisible to ecashlib since
 * ecashlib does not do any networking.  That is: the ecashlib never 
 * creates or reads an EC_Address-- it just passes them from 
 * application level to application level.
 *
 * The formats for various kinds EC_Address (e.g. TCP/IP, e-mail, 
 * and future networking protocols) will be developed by DigiCash
 * in conjunction with application developers.
 */


typedef Byte *EC_Address;

EC_Errno EC_addr_free(EC_Address *address_ptr);



   /* EC_Amount */

/* An EC_Amount is a signed 32-bit integer.  It represents an amount 
 * of money in units of the coinage's base value.  
 */


typedef Int32 EC_Amount;



   /* EC_Protocol */

/* The protocol.  Currently, there is only one: the ecash 2.x
 * online cash protocol.
 */
typedef enum 
{
   EC_PROTOCOL_ECASH_ONLINE_COINS = 2
} EC_Protocol;







   /* EC_CurrID */

/* An EC_CurrID uniquely identifies a currency.  The list of
 * currencies is maintained by DigiCash.
 */


typedef UInt32 EC_CurrID;



   /* EC_Coinage */

/* An EC_Coinage is a data type which contains some information
 * about the ecash.
 *
 * An EC_Coinage has four qualities:
 * 1.  An issuer.
 * 2.  A currency.  Ecash is exchangeable at the issuer for this
 *   currency.
 * 3.  A base value.  This is the smallest value that can be
 *   exchanged in ecash of this kind.
 * 4.  A granularity.  This is the degree of precision that is
 *   commonly used when representing amounts of this kind of ecash 
 *   to a user.
 *
 *
 * The way this is implemented is as follows:
 * 1. Each EC_Coinage has an EC_MintID to identify the issuer.
 * 2. Each EC_Coinage has an EC_CurrencyID to identify the currency.
 * 3. Each EC_Coinage has a pair of 32-bit numbers to identify the 
 *   base value.  The first of these numbers is signed and identifies 
 *   the order of magnitude (power of ten) of the base value.  (For 
 *   example -2 to indicate that the base value is on the order of 
 *   0.01.)  
 *   The second of these numbers is unsigned and indicates the
 *   factor which determines the base value within that order of
 *   magnitude.  (In the example, a factor of 1 would mean that the
 *   base value is 0.01, and a factor of 5 would mean that the base
 *   value is 0.05.)
 * 4. Each EC_Coinage has a signed 32-bit number to identify the
 *   granularity.  (For example, -2 to indicate that a precision of
 *   0.01 is used when displaying amounts in this EC_Coinage.)
 */
typedef struct EC_Coinage EC_Coinage;



   /* EC_Coinage functions */


/* Free an EC_Coinage. */
EC_Errno EC_coinage_free(EC_Coinage *coinage_ptr);

EC_MintID EC_coinage_get_mintID(EC_Coinage *coinage_ptr);

EC_CurrID EC_coinage_get_currID(EC_Coinage *coinage_ptr);

Int32 EC_coinage_get_base_magn(EC_Coinage *coinage_ptr);

UInt32 EC_coinage_get_base_factor(EC_Coinage *coinage_ptr);

Int32 EC_coinage_get_granularity(EC_Coinage *coinage_ptr);



   /* General Ecashlib functions */

/* Initialize the package by specifying ANSI C-style memory
 * allocation, reallocation and deallocation, as well as a 
 * log function.  The log function is called with two 
 * parameters, a string to log and a logging level.
 *
 * The realloc function must handle a NULL "data_ptr" parameter by
 * allocating a new block of the appropriate size and setting
 * data_ptr to point to it.
 *
 * If a NULL pointer is passed instead of the "malloc", "realloc"
 * or "free" function then ecashlib will try to use standard
 * functions in their place.  This will not work on all platforms.
 *
 * The "yield" function will get called frequently when ecashlib is
 * doing computation-intensive functions.  If a NULL pointer is
 * passed instead of the "yield" function then it will not be
 * called.
 */
EC_Errno EC_main_init(void *malloc(size_t size), 
   void *realloc(void *data_ptr, size_t size), 
   void free(void *data_ptr), 
   void yield(int this_is_the_last_yield),
   void log(EC_LogLevel level, const char *text_str));

/* What version of the ecashlib is this?
 * The return value is of the format "xx.yyy.zzz {keywords ...}"
 * where xx is the major version number, yyy is the minor version
 * number (which involves a change to the API) and zzz is the
 * patchlevel.  Finally optional keywords may follow.
 */
char *EC_main_get_libver();

/* Clean_up will cause ecashlib to clean up its files and internal 
 * memory allocation.  It also unlocks any files or callbacks that
 * it may have locked.  Call this as the last thing, after you have 
 * freed all EC_ data-structures that you were responsible for.
 */
EC_Errno EC_main_cleanup(void);



   /* EC_Coinage string conversion functions. */

/* These are just for convenience.  You may safely ignore them. */

/* Convert a string to a currency ID.
 * name_str: a string identifying the currency.  This can be any of 
 *    several strings such as the 3-letter abbreviation (e.g. "USD"), 
 *    the full name (e.g. "United States Dollar") and perhaps some 
 *    alternate names (e.g. "U.S. Dollar" or "US$").  The list of 
 *    which alternate names are understood by this function is 
 *    maintained by DigiCash.
 * currID_ptr: the currency, if it could be identified.
 */
EC_Errno EC_main_str_to_curr(const char *name_str, 
   EC_CurrID *currID_ptr);

/* Convert a currency ID to the currency's abbreviation.
 * currID: the currency
 * abbr_ypn: the 3-letter abbreviation for that currency.  The list
 *    of currencies and their 3-letter abbreviations is maintained
 *    by DigiCash.
 */
EC_Errno EC_main_curr_to_abbr(EC_CurrID currID, char **abbr_ypn);

/* Convert a currency ID to the currency's name.
 * currID: the currency
 * name_ypn: the full name for that currency.  The list of
 *    currencies and their names is maintained by DigiCash.
 */
EC_Errno EC_main_curr_to_name(EC_CurrID currID, char **name_ypn);

/* Convert an EC_Amount and EC_Coinage to its string representation.
 * amount: the amount
 * coinage: the coinage of ecash that the amount is in
 * string_ypn: the string representation of that amount and coinage
 */
EC_Errno EC_main_value_to_str(EC_Amount amount, EC_Coinage *coinage,
   char **string_ypn);






   /* EC_Info */

/* EC_Info contains information about an account: account ID, 
 * information about the user, the bank, balance, currency, etc.  
 * It provides a snap-shot of the account at the time that
 * the EC_Info was created.
 */
typedef struct EC_Info_s EC_Info;



   /* EC_Info functions */


/* Free account information structure. */
EC_Errno EC_info_free(EC_Info *info_ptr);

/* Get the account ID. */
EC_AccountID *EC_info_get_accountID(EC_Info *info_ptr);

char *EC_info_get_account_info(EC_Info *info_ptr);

/* Get the mint ID. */
EC_MintID EC_info_get_mintID(EC_Info *info_ptr);

char *EC_info_get_mint_info(EC_Info *info_ptr);

/* Get the mint address. */
EC_Address *EC_info_get_mint_address(EC_Info *info_ptr);

/* Get the coinage for this account. */
EC_Coinage *EC_info_get_coinage(EC_Info *info_ptr);

/* Get the amount in cash for this account. */
EC_Amount *EC_info_get_cash(EC_Info *info_ptr);

/* Get the amount stored at the mint for this account. */
EC_Amount *EC_info_get_balance(EC_Info *info_ptr);

/* Get the amount in expired cash for this account. */
EC_Amount *EC_info_get_exp_cash(EC_Info *info_ptr);

/* Get the number of payments guaranteed to be payable using the 
 * current coins. 
 */
UInt16 EC_info_min_pay(EC_Info *info_ptr);






   /* EC_Account */

/* An EC_Account contains information about a bank account */


typedef struct EC_Account_s EC_Account;



   /* Account functions */ 


/* Get an account handle.  Note that a password always has to be supplied
 * (so all account information & cash can be stored encrypted)
 */
EC_Errno EC_main_acquire_account(EC_AccountID accountID, 
   const char *passwd_str, EC_Account **account_ypn);

/* set a different password for this account */
EC_Errno EC_acc_passwd(EC_Account *account_ptr, 
   const char *passwd_str, const char *old_passwd_str);

/* release a handle for an account */
EC_Errno EC_acc_release(EC_Account *account_ptr);

/* Get information about an account. */
EC_Errno EC_acc_get_info(EC_Account *account_ptr, EC_Info **info_ypn);

/* Get a record list for an account. */
EC_Errno EC_acc_get_rlist(EC_Account *account_ptr, 
   EC_RecordList **rlist_ypn);



   /* Account "Complex Action" functions */

/* These are Account functions which initiate an complex action--an 
 * action that cannot be completed without some networking services
 * being performed by the application on behalf of the ecashlib.
 * When an "EC_acc_begin" function is called an EC_ActionHandler will 
 * be created to handle the complex action.
 */


/* Create an account.
 * mintID, mint_address: ID and address of the bank
 * accountID, acc_info_str: account ID and info for user
 * bank_passwd_str: password needed to open the account
 * acc_passwd_srt: password used to secure the account
 * rnd_data_str: random data used for recovery
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 * account_ypn: once the account creation is completed
 *   account_ypn will point to the newly created account.
 */
EC_Errno EC_begin_account_creation(EC_MintID mintID,
   EC_Address bank_address, EC_AccountID accountID, 
   const char *acc_info_str, const char *bank_passwd_str, 
   const char *acc_passwd_str, const char *rnd_data_str,
   EC_ActionHandler **acth_ypn, EC_Account **account_ypn);

/* Withdraw cash.
 * account_ptr: account handle
 * amount: amount to withdraw
 * minpay: the minimum number of payments that can be made after this
 *    withdrawal
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_withdrawal(EC_Account *account_ptr, 
   EC_Amount amount, UInt32 minpay, EC_ActionHandler **acth_ypn);

/* Deposit cash.
 * account_ptr: account handle
 * amount: amount to deposit
 * minpay: the minimum number of payments that can be made after this
 *    deposit
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_deposit(EC_Account *account_ptr, 
   EC_Amount amount_str, UInt32 minpay, EC_ActionHandler **acth_ypn);

/* Make payment.
 * account_ptr: account handle
 * protocol_ptr: protocol to use for payment
 * amount: amount to pay
 * description_str: payment description or NULL
 * recip_accID, recip_addr: account ID and address of recipient
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_make_payment(EC_Account *account_ptr, 
   EC_Protocol *protocol_ptr, EC_Amount amount,
   const char *description_str, EC_AccountID recip_accID, 
   EC_Address recip_addr, EC_ActionHandler **acth_ypn);

/* Accept incoming payment.
 * account_ptr: account handle
 * payment: the EC_Msg which contains the payment
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_accept_payment(EC_Account *account_ptr, 
   EC_Msg *payment, EC_ActionHandler **acth_ypn);

/* Request payment.
 * account_ptr: account handle
 * protocol_ptr: protocol to use for payment
 * amount: amount to request
 * description_str: payment description or NULL
 * requestee_accID, requestee_addr: ID and address of 
 *    requestee
 * return_addr: the address which the payment should be sent
 *    to if different from the account's normal address.  This
 *    is an optional parameter which will be ignored if a null
 *    address (the NULL pointer or a zero-length string) is passed.
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_request_payment(EC_Account *account_ptr, 
   EC_Protocol *protocol_ptr, EC_Amount amount,
   const char *description_str, EC_AccountID requestee_accID,
   EC_Address requestee_addr, EC_Address return_addr,
   EC_ActionHandler **acth_ypn);

/* Cancel a payment from a record.
 * account_ptr: account handle
 * payment_ptr: a record of the payment
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_cancel_payment(EC_Account *account_ptr,
   EC_PaymentRecord *payment_ptr, EC_ActionHandler **acth_ypn);

/* Resend a payment from a record.
 * account_ptr: account handle
 * payment_ptr: a record of the payment
 * acth_ypn: an action handler will be created to handle this
 *    action and a pointer to it will be passed back in acth_ypn.
 */
EC_Errno EC_acc_begin_resend_payment(EC_Account *account_ptr,
   EC_PaymentRecord *payment_ptr, EC_ActionHandler **acth_ypn);






   /* EC_StateType */

/* Each action handler has an EC_StateType which, along with EC_Errno, 
 * reflects its current state.  
 *
 *   EC_STATE_NEED_SEND_MSG
 * Indicates that the application needs to send a message in order 
 * for the action handler to continue.  The application can find out 
 * what message needs to be sent and what address to send it to be 
 * calling EC_acth_get_msg().
 *   
 *   EC_STATE_NEED_RECEIVE_MSG
 * Indicates that the action handler needs a message in order to 
 * continue.
 * 
 *   EC_STATE_DONE
 * Indicates that the action for this action handler is done.
 * The action handler's EC_Errno is set to indicate whether this
 * state was reached by successful completion of the action or
 * by some exceptional condition.
 */


typedef enum
{
   EC_STATE_NEED_SEND_MSG = 1,
   EC_STATE_NEED_RECEIVE_MSG = 2,
   EC_STATE_DONE = 0
} EC_StateType;



   /* Action handler functions */


/* Free the action handler.
 * If this handler's state is not EC_STATE_DONE, then the 
 * EC_ActionHandler will _not_ be freed and EC_acth_free will return 
 * an EC_ERR_ACTH_MANAGEMENT.
 */
EC_Errno EC_acth_free(EC_ActionHandler *action_handler_ptr);

/* Abort the current action. */
EC_Errno EC_acth_abort_action(EC_ActionHandler *action_handler_ptr);

/* Get a communication which was passed to the ecashlib by another 
 * ecash application via an EC_Msg.  If the last EC_Msg that was
 * processed by this action handler contained a communication then
 * this call will return that communication.
 */
EC_Errno EC_acth_get_communication(EC_ActionHandler *action_handler_ptr,
   UInt32 *comm_int, char **comm_str_ypn);



   /* interactions between the action handler and the application */

EC_StateType EC_acth_get_state(EC_ActionHandler *action_handler_ptr);

/* Get information about message to be sent. */
EC_Errno EC_acth_get_msg(EC_ActionHandler *action_handler_ptr, 
   EC_Msg **msg_ypn, EC_Address **address_ypn);

/* Give a message which has been received to the action handler.
 * The "sender_addr" parameter is optional-- NULL or an empty
 *    address may be passed instead of the sender's address.  This 
 *    information is only stored in records-- it is not acted upon.
 */
EC_Errno EC_acth_process_msg(EC_ActionHandler *action_handler_ptr,
   EC_Msg *message, EC_Address *sender_addr);

/* Get the action handler's error state.
 * The return value is the EC_Errno which is contained by the 
 * action handler as a part of its state.
 */
EC_Errno EC_acth_get_errno(EC_ActionHandler *action_handler_ptr);

/* Get info about the account that this action handler is uses.
 * info_ypn: This EC_Info is frozen when the action is completed or
 * aborted, yielding a snap-shot of the state of the account at that 
 * moment.  Calling EC_acth_get_info() before that time is equivalent
 * to calling EC_acc_get_info().
 */
EC_Errno EC_acth_get_info(EC_ActionHandler *action_handler_ptr,
   EC_Info **info_ypn);






   /* EC_MsgType */

/* There are currently three kinds of messages from the application's
 * point of view: payments, payment requests, and "other" 
 * (none-of-the-above).  Currently all synchronous messages fall into 
 * the "other" category.
 */
typedef enum
{
   EC_MSGTYPE_PAYMENT = 0,
   EC_MSGTYPE_PAYREQ = 1,
   EC_MSGTYPE_OTHER = 2
} EC_MsgType;



   /* EC_Msg Functions */


/* Free an EC_Msg. */
EC_Errno EC_msg_free(EC_Msg *message);

/* Create a new EC_Msg with msg_size size and msg_contents
 * contents.  EC_msg_new will make a copy of msg_contents, so 
 * you may free msg_contents after calling EC_msg_new().  The
 * format of msg_contents is opaque to the application-- no
 * knowledge about msg_contents internals should be used in the 
 * application.
 * msg_size: the size of the msg_contents data.
 * msg_contents: a pointer to a block of a data of size msg_size
 *    containing the message contents.  This data was generated by
 *    an ecash application via a call to EC_msg_get_data() and was
 *    transmitted to _your_ application.
 * msg_ypn: the new message will be referenced by msg_ypn.
 */
EC_Errno EC_msg_new(UInt32 msg_size, const Byte *msg_contents, 
   EC_Msg **msg_ypn);

/* Get the information about an EC_Msg that you need to know
 * in order to transmit the EC_Msg to another ecash
 * application.  It is up to the application how to transmit this
 * data.  Note that this data is valid exactly as long as the EC_Msg
 * itself still exists-- this data will become invalid when 
 * EC_msg_free() is called on this EC_Msg.
 */
UInt32 EC_msg_get_size(EC_Msg *message);

const Byte *EC_msg_get_contents(EC_Msg *message);

/* Get information about the type of message. */
EC_MsgType EC_msg_get_type(EC_Msg *message);



   /* EC_Msg Functions for asynchronous messages */

/* "Asynchronous messages" are those messages which arrive as the 
 * start of a new conversation rather than as the continuation of
 * an existing conversation.
 */


/* Get the payment info from a payment EC_Msg.
 * Returns an error if called on an EC_Msg which is not a payment.
 */
EC_Errno EC_msg_get_pay_info(EC_Msg *message, 
   EC_Coinage **coinage_ypn, EC_Amount *amount_ptr,
   char **desc_ypn, EC_MintID *mintID_ptr);

/* Get the payment-request info from a payment-request EC_Msg.
 * Returns an error if called on an EC_Msg which is not a payment 
 * request.
 * account_ptr: this is a pointer to an account which you are 
 *    considering using to pay.  Thus if the payment request includes
 *    requests for multiple coinages EC_msg_get_payreq_info will 
 *    return info about the request which the account is capable of 
 *    satisfying.
 */
EC_Errno EC_msg_get_payreq_info(EC_Msg *message, 
   EC_Account *account_ptr, EC_AccountID *accID_ptr,
   EC_Address **addr_ypn, EC_Amount *amount_ptr,
   char **desc_ypn, EC_MintID *mintID_ptr);






   /* EC_RecordList functions */


/* Read the next record from a record list. */
EC_Record *EC_rlist_read_record(EC_RecordList *rlist_ptr);

/* Free a record list. */
EC_Errno EC_rlist_free(EC_RecordList *rlist_ptr);

/* Delete all but the last num entries in a record list.
 * Note that once a record has been deleted you can no longer cancel
 * or re-send that payment.  On the other hand it may be wasteful of
 * resources to keep _all_ records forever.  The application should 
 * never call EC_rlist_snip() on records that it might want to
 * cancel or resend, but it _should_ call EC_rlist_snip() on
 * records that it will never want to cancel or resend.
 */
EC_Errno EC_rlist_snip(EC_RecordList *rlist_ptr, UInt32 num);



typedef enum
{
   EC_RTYPE_PREC = 0,
   EC_RTYPE_BOOKING = 1
} EC_RecordType;



   /* EC_Record functions */


/* Free a record. */
EC_Errno EC_rec_free(EC_Record *record_ptr);

/* Find out what kind of record this is. */
EC_RecordType EC_rec_get_type(EC_Record *record_ptr);

/* Get the EC_PaymentRecord from this record.  Returns an error if
 * called on an EC_Record which is not a payment record.
 */
EC_Errno EC_rec_get_prec(EC_Record *record_ptr, 
   EC_PaymentRecord **prec_ypn);

/* Get the EC_Booking from this record.  Returns an error if called
 * on an EC_Record which is not a booking.
 */
EC_Errno EC_rec_get_booking(EC_Record *record_ptr, 
   EC_Booking **booking_ypn);



typedef enum
{
   EC_TRAN_STATE_UNFINISHED = 0,
   EC_TRAN_STATE_SUCCESSFUL = 1,
   EC_TRAN_STATE_REJECTED = 2,
   EC_TRAN_STATE_CANCELLED = 3,
   EC_TRAN_STATE_ERROR = 4
} EC_TransactionState;


   /* EC_PaymentRecord functions. */

EC_Errno EC_prec_free(EC_Record *record_ptr);

/* Get the info about the payment from a payment record. */
EC_Address *EC_prec_payer_address(EC_Record *record_ptr);

/* Get the Account ID of the recipient from a payment record. */
EC_AccountID *EC_prec_recip_ID(EC_Record *record_ptr);

/* Get the amount of the payment from a payment record. */
EC_Amount EC_prec_amount(EC_Record *record_ptr);

/* Get the time of the payment from a payment record.
 * The return value is an unsigned 32-bit integer representing
 * seconds since 00:00:00 UTC Jan. 1, 1970.
 */
UInt32 EC_prec_time(EC_Record *record_ptr);

/* Get the description of the payment from a payment record. */
char *EC_prec_desc(EC_Record *record_ptr);

/* Get the state of a payment from a payment record. */
EC_TransactionState EC_prec_get_state(EC_PaymentRecord *prec_ptr);

typedef enum
{
   EC_BOOKINGTYPE_WITHDRAWAL = 0,
   EC_BOOKINGTYPE_DEPOSIT = 1,
   EC_BOOKINGTYPE_ACCEPT_PAYMENT = 2
} EC_BookingType;


   /* EC_Booking functions */

EC_Errno EC_book_free(EC_Booking *book_ptr);

/* Get booking type. */
EC_BookingType EC_book_get_type(EC_Booking *book_ptr);

/* Get the amount. */
EC_Amount EC_book_amount(EC_Booking *book_ptr);

/* Get the time the transaction was initiated.
 * The return value is an unsigned 32-bit integer representing
 * seconds since 00:00:00 UTC Jan. 1, 1970.
 */
UInt32 EC_book_start_time(EC_Booking *book_ptr);

/* Get the time that the transaction was completed.
 * The return value is an unsigned 32-bit integer representing
 * seconds since 00:00:00 UTC Jan. 1, 1970.
 */
UInt32 EC_book_end_time(EC_Booking *book_ptr);

/* Get the description of the booking. */
char *EC_book_desc(EC_Booking *book_ptr);

/* Get the state of a booking. */
EC_TransactionState EC_book_get_state(EC_Booking *book_ptr);


#endif


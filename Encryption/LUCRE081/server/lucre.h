#ifndef EC_INCL_LUCRE_H
#define EC_INCL_LUCRE_H

#include <stdio.h>
#include <sys/types.h>
#include "ecash.h"
#include "bn.h"
#include "db.h"

/* The global functions passed in EC_main_init */
extern void* (*EC_G_malloc)(size_t size);
extern void* (*EC_G_realloc)(void *ptr, size_t size);
extern void (*EC_G_free)(void *ptr);
extern void (*EC_G_yield)(int last_yield);
extern void (*EC_G_log)(EC_LogLevel level, const char *text_str);

/* The global helper functions */
char *EC_G_strdup(char *str);
Int32 EC_G_write_out(Byte *data, UInt32 len, void *state);
Int32 EC_G_read_in(Byte *data, UInt32 len, void *state);


/* The basic compiled Message */
typedef struct EC_M_Msg_s {
    Byte *data;
    UInt32 alloc;
    UInt32 begin;
    UInt32 end;
    struct EC_M_Msg_s *next;
} * EC_M_Msg;

typedef struct {
    UInt32 begin;
    UInt32 end;
} EC_M_Msgpos;

/* Field types */
typedef enum {
    EC_M_FIELD_NONE,
    EC_M_FIELD_INT,
    EC_M_FIELD_TIME,
    EC_M_FIELD_STRING,
    EC_M_FIELD_MPI,
    EC_M_FIELD_DATA,
    EC_M_FIELD_SOR,
    EC_M_FIELD_EOR
} EC_M_Fieldtype;

/* Record types, in the event the Field type is EC_M_FIELD_SOR */
typedef enum {
    /* The following record types are the same as, or at least compatible
       with (hopefully) the equivalent records in DigiCash's software.
       This is necessary for interoperability. */

    EC_M_REC_NONE = 0,
    EC_M_REC_SETUP = 1,
    EC_M_REC_CURR = 2,
    EC_M_REC_OPENACC1 = 3,
    EC_M_REC_OPENACC2 = 4,
    EC_M_REC_OPENACC3 = 5,
    EC_M_REC_WITHDRAW1 = 6,
    EC_M_REC_WITHDRAW2 = 7,
    EC_M_REC_WITHDRAW3 = 8,
    EC_M_REC_WITHDRAW4 = 9,
    EC_M_REC_PAYMENT = 10,
    EC_M_REC_DEPOSIT = 11,
    EC_M_REC_DEP_ACK = 12,
    EC_M_REC_ERROR = 13,
    EC_M_REC_BANKEY = 14,
    EC_M_REC_BANKHDR = 15,
    EC_M_REC_PAYREQ = 18,
    EC_M_REC_QUIT = 19,
    EC_M_REC_DONE = 20,
    EC_M_REC_SETUP_REQ = 22,
    EC_M_REC_STATEMENT = 23,
    EC_M_REC_MESSAGE = 26,
    EC_M_REC_HDR_STUFF = 40,
    EC_M_REC_BANK_MKEY = 41,
    EC_M_REC_CINFO = 42,
    EC_M_REC_ONL_COIN = 43,
    EC_M_REC_PAYMENT_HDR = 46,
    EC_M_REC_USERKEY = 47,
    EC_M_REC_USERHDR = 48,
    EC_M_REC_USERINFO = 49,
    EC_M_REC_SIGMSG = 50,
    EC_M_REC_SIGLEN = 51,
    EC_M_REC_WDFIN = 53,
    EC_M_REC_DEP = 54,
    EC_M_REC_DEP_1ACK = 55,
    EC_M_REC_PCOINS = 56,
    EC_M_REC_PROTOCOLS = 58,
    EC_M_REC_PROT_SETUP = 59,
    EC_M_REC_BANK_REPL = 60,
    EC_M_REC_ENCRYPT = 62,
    EC_M_REC_USERPRIVKEY = 63,
    EC_M_REC_USERPRIVENC = 64,
    EC_M_REC_USERREC = 65,
    EC_M_REC_STATUS = 66,
    EC_M_REC_ONL_CURR = 67,
    EC_M_REC_RSAENC = 68,
    EC_M_REC_BANK_ENCR = 69,

    /* The following record types are probably not compatible with the
       equivalent record types from DigiCash's software, but since they're
       all internal, it shouldn't matter. */

    EC_M_REC_COINDATA = 45,

} EC_M_Rectype;

typedef union {
    UInt32 intval;
    time_t timeval;
    char * stringval;
    BIGNUM * MPIval;
    struct { Byte * data; UInt32 len; } dataval;
    EC_M_Rectype rectype;
} EC_M_Fieldval;

void EC_M_free_fieldval(EC_M_Fieldtype fieldtype, EC_M_Fieldval fieldval);

/* Protocol types */
typedef enum {
    EC_M_PROT_ONLINE_COINS = 2,
} EC_M_Protocol;

/* Encryption algorithms */
typedef enum {
    EC_M_CRYPTALG_NONE = 0,
    EC_M_CRYPTALG_112_3DES = 1,
} EC_M_Cryptalg;

/* Signature algorithms */
typedef enum {
    EC_M_SIGALG_NONE = 0,
    EC_M_SIGALG_SHA1 = 0x92,
} EC_M_Sigalg;

/* Currency types */
typedef enum {
    EC_M_CURRENCY_CYBERBUCKS = 1,
    EC_M_CURRENCY_US_CENTS = 4,
} EC_M_Currency;

/* These bits of a keyversion represent the value of the coin */
#define EC_M_KEYVER_VALMASK 0x1f

/* Error codes, in an ERROR message */
typedef enum {
    EC_M_ERROR_NONE = 0,
} EC_M_Errno;

/* Message constuctors and destructors */
EC_M_Msg EC_M_new_msg(void);
EC_M_Msg EC_M_clone_msg(EC_M_Msg msg);
UInt32 EC_M_cmp_msg(EC_M_Msg msg1, EC_M_Msg msg2);
void EC_M_free_msg(EC_M_Msg msg);
void EC_M_clear_msg(EC_M_Msg msg);
EC_Errno EC_M_append_msg(Byte *data, UInt32 len, EC_M_Msg msg);
EC_M_Msgpos EC_M_tell_msg(EC_M_Msg msg);
EC_Errno EC_M_seek_msg(EC_M_Msgpos pos, EC_M_Msg msg);
EC_Errno EC_M_rewind_msg(EC_M_Msg msg);
EC_Errno EC_M_transfer_field(EC_M_Msg from, EC_M_Msg to);
BIGNUM *EC_M_clone_MPI(BIGNUM *mpi);
UInt32 EC_M_cmp_MPI(BIGNUM *mpi1, BIGNUM *mpi2);
void EC_M_free_MPI(BIGNUM *mpi);
Byte *EC_M_clone_data(Byte *data, UInt32 len);
UInt32 EC_M_cmp_data(Byte *data1, Byte *data2, UInt32 len);
void EC_M_free_data(Byte *data);

/* Field constructors */
EC_Errno EC_M_compile_int(UInt32 val, EC_M_Msg msg);
EC_Errno EC_M_compile_time(time_t val, EC_M_Msg msg);
EC_Errno EC_M_compile_string(char *val, EC_M_Msg msg);
EC_Errno EC_M_compile_MPI(BIGNUM *val, EC_M_Msg msg);
EC_Errno EC_M_compile_data(Byte *val, UInt32 len, EC_M_Msg msg);
EC_Errno EC_M_compile_sor(EC_M_Rectype type, EC_M_Msg msg);
EC_Errno EC_M_compile_eor(EC_M_Msg msg);

/* Field readers */
EC_Errno EC_M_examine_msg(EC_M_Fieldtype *fieldtype, EC_M_Rectype *rectype,
    EC_M_Msg msg);
EC_Errno EC_M_decompile_int(UInt32 *val, EC_M_Msg msg);
EC_Errno EC_M_decompile_time(time_t *val, EC_M_Msg msg);
EC_Errno EC_M_decompile_string(char **val, EC_M_Msg msg);
EC_Errno EC_M_decompile_MPI(BIGNUM **val, EC_M_Msg msg);
EC_Errno EC_M_decompile_data(Byte **val, UInt32 *len, EC_M_Msg msg);
EC_Errno EC_M_decompile_sor(EC_M_Rectype type, EC_M_Msg msg);
EC_Errno EC_M_decompile_eor(EC_M_Msg msg);

/* Message types and their handlers */

/* Setup Request */
typedef UInt32 EC_M_Setup_req;

EC_M_Setup_req EC_M_new_setup_req(void);
EC_Errno EC_M_examine_setup_req(EC_M_Setup_req setup_req);
EC_M_Setup_req EC_M_clone_setup_req(EC_M_Setup_req setup_req);
UInt32 EC_M_cmp_setup_req(EC_M_Setup_req setup_req1,
    EC_M_Setup_req setup_req2);
void EC_M_free_setup_req(EC_M_Setup_req setup_req);
EC_Errno EC_M_compile_setup_req(EC_M_Setup_req setup_req, EC_M_Msg msg);
EC_Errno EC_M_decompile_setup_req(EC_M_Setup_req *setup_req, EC_M_Msg msg);

/* Header for transmission to bank */
typedef struct EC_M_Hdr_stuff_s {
    UInt32 version;
    time_t timestamp;
} * EC_M_Hdr_stuff;

EC_M_Hdr_stuff EC_M_new_hdr_stuff(UInt32 version, time_t timestamp);
EC_M_Hdr_stuff EC_M_clone_hdr_stuff(EC_M_Hdr_stuff hdr_stuff);
EC_Errno EC_M_examine_hdr_stuff(EC_M_Hdr_stuff hdr_stuff, UInt32 *version,
    time_t *timestamp);
UInt32 EC_M_cmp_hdr_stuff(EC_M_Hdr_stuff hdr_stuff1,
    EC_M_Hdr_stuff hdr_stuff2);
void EC_M_free_hdr_stuff(EC_M_Hdr_stuff hdr_stuff);
EC_Errno EC_M_compile_hdr_stuff(EC_M_Hdr_stuff hdr_stuff, EC_M_Msg msg);
EC_Errno EC_M_decompile_hdr_stuff(EC_M_Hdr_stuff *hdr_stuff, EC_M_Msg msg);

/* Signed message */
typedef struct EC_M_Sigmsg_s {
    UInt32 algorithm;
    BIGNUM *signature;
    EC_M_Msg msg;
} * EC_M_Sigmsg;

EC_M_Sigmsg EC_M_new_sigmsg(EC_M_Sigalg algorithm, BIGNUM *signature,
    EC_M_Msg msg);
EC_M_Sigmsg EC_M_clone_sigmsg(EC_M_Sigmsg sigmsg);
EC_Errno EC_M_examine_sigmsg(EC_M_Sigmsg sigmsg, EC_M_Sigalg *algorithm,
    BIGNUM **signature, EC_M_Msg *msg);
UInt32 EC_M_cmp_sigmsg(EC_M_Sigmsg sigmsg1, EC_M_Sigmsg sigmsg2);
void EC_M_free_sigmsg(EC_M_Sigmsg sigmsg);
EC_Errno EC_M_compile_sigmsg(EC_M_Sigmsg sigmsg, EC_M_Msg msg);
EC_Errno EC_M_decompile_sigmsg(EC_M_Sigmsg *sigmsg, EC_M_Msg msg);

/* SETUP message */
typedef struct EC_M_Setup_s {
    EC_M_Sigmsg sigmsg;
} * EC_M_Setup;

EC_M_Setup EC_M_new_setup(EC_M_Sigmsg sigmsg);
EC_M_Setup EC_M_clone_setup(EC_M_Setup setup);
EC_Errno EC_M_examine_setup(EC_M_Setup setup, EC_M_Sigmsg *sigmsg);
UInt32 EC_M_cmp_setup(EC_M_Setup setup1, EC_M_Setup setup2);
void EC_M_free_setup(EC_M_Setup setup);
EC_Errno EC_M_compile_setup(EC_M_Setup setup, EC_M_Msg msg);
EC_Errno EC_M_decompile_setup(EC_M_Setup *setup, EC_M_Msg msg);

/* BANK_MKEY message */
typedef struct EC_M_Bank_mkey_s {
    UInt32 bankID;
    UInt32 keynumber;
    time_t timestamp;
    char *bankname;
    char *bankemail;
    UInt32 numaddrs;
    char **bankaddr;
    UInt32 withdrawindex;
    UInt32 bankport;
    BIGNUM *bank_n;
    BIGNUM *bank_e;
    UInt32 maxcoins;
} * EC_M_Bank_mkey;

EC_M_Bank_mkey EC_M_new_bank_mkey(UInt32 bankID, UInt32 keynumber,
    time_t timestamp, char *bankname, char *bankemail, UInt32 numaddrs,
    char **bankaddr, UInt32 withdrawindex, UInt32 bankport,
    BIGNUM *bank_n, BIGNUM *bank_e, UInt32 maxcoins);
EC_M_Bank_mkey EC_M_clone_bank_mkey(EC_M_Bank_mkey bank_mkey);
EC_Errno EC_M_examine_bank_mkey(EC_M_Bank_mkey bank_mkey,
    UInt32 *bankID, UInt32 *keynumber,
    time_t *timestamp, char **bankname, char **bankemail, UInt32 *numaddrs,
    char ***bankaddr, UInt32 *withdrawindex, UInt32 *bankport,
    BIGNUM **bank_n, BIGNUM **bank_e, UInt32 *maxcoins);
UInt32 EC_M_cmp_bank_mkey(EC_M_Bank_mkey bank_mkey1,
    EC_M_Bank_mkey bank_mkey2);
void EC_M_free_bank_mkey(EC_M_Bank_mkey bank_mkey);
EC_Errno EC_M_compile_bank_mkey(EC_M_Bank_mkey bank_mkey, EC_M_Msg msg);
EC_Errno EC_M_decompile_bank_mkey(EC_M_Bank_mkey *bank_mkey, EC_M_Msg msg);

typedef struct EC_M_Prot_setup_s {
    EC_M_Protocol protocol;
} * EC_M_Prot_setup;

EC_M_Prot_setup EC_M_new_prot_setup(EC_M_Protocol protocol);
EC_M_Prot_setup EC_M_clone_prot_setup(EC_M_Prot_setup prot_setup);
EC_Errno EC_M_examine_prot_setup(EC_M_Prot_setup prot_setup,
    EC_M_Protocol *protocol);
UInt32 EC_M_cmp_prot_setup(EC_M_Prot_setup prot_setup1,
    EC_M_Prot_setup prot_setup2);
void EC_M_free_prot_setup(EC_M_Prot_setup prot_setup);
EC_Errno EC_M_compile_prot_setup(EC_M_Prot_setup prot_setup, EC_M_Msg msg);
EC_Errno EC_M_decompile_prot_setup(EC_M_Prot_setup *prot_setup, EC_M_Msg msg);

typedef struct EC_M_Protocols_s {
    UInt32 numprots;
    EC_M_Prot_setup *prot_setup;
} * EC_M_Protocols;

EC_M_Protocols EC_M_new_protocols(UInt32 numprots,
    EC_M_Prot_setup *prot_setup);
EC_M_Protocols EC_M_clone_protocols(EC_M_Protocols protocols);
EC_Errno EC_M_examine_protocols(EC_M_Protocols protocols, UInt32 *numprots,
    EC_M_Prot_setup **prot_setup);
UInt32 EC_M_cmp_protocols(EC_M_Protocols protocols1,
    EC_M_Protocols protocols2);
void EC_M_free_protocols(EC_M_Protocols protocols);
EC_Errno EC_M_compile_protocols(EC_M_Protocols protocols, EC_M_Msg msg);
EC_Errno EC_M_decompile_protocols(EC_M_Protocols *protocols, EC_M_Msg msg);

typedef struct EC_M_Userinfo_s {
    char *accID;
    char *name;
    char *email;
    UInt32 currency;
} * EC_M_Userinfo;

EC_M_Userinfo EC_M_new_userinfo(char *accID, char *name, char *email,
    EC_M_Currency currency);
EC_M_Userinfo EC_M_clone_userinfo(EC_M_Userinfo userinfo);
EC_Errno EC_M_examine_userinfo(EC_M_Userinfo userinfo, char **accID,
    char **name, char **email, EC_M_Currency *currency);
UInt32 EC_M_cmp_userinfo(EC_M_Userinfo userinfo1, EC_M_Userinfo userinfo2);
void EC_M_free_userinfo(EC_M_Userinfo userinfo);
EC_Errno EC_M_compile_userinfo(EC_M_Userinfo userinfo, EC_M_Msg msg);
EC_Errno EC_M_decompile_userinfo(EC_M_Userinfo *userinfo, EC_M_Msg msg);

typedef struct EC_M_Openacc1_s {
    EC_M_Userinfo userinfo;
    BIGNUM *n;
    BIGNUM *e;
    EC_M_Protocol protocol;
    UInt32 keyno;
    char *password;
} * EC_M_Openacc1;

EC_M_Openacc1 EC_M_new_openacc1(EC_M_Userinfo userinfo, BIGNUM *n,
    BIGNUM *e, EC_M_Protocol protocol, UInt32 keyno, char *password);
EC_M_Openacc1 EC_M_clone_openacc1(EC_M_Openacc1 openacc1);
EC_Errno EC_M_examine_openacc1(EC_M_Openacc1 openacc1, EC_M_Userinfo *userinfo,
    BIGNUM **n, BIGNUM **e, EC_M_Protocol *protocol, UInt32 *keyno,
    char **password);
UInt32 EC_M_cmp_openacc1(EC_M_Openacc1 openacc11, EC_M_Openacc1 openacc12);
void EC_M_free_openacc1(EC_M_Openacc1 openacc1);
EC_Errno EC_M_compile_openacc1(EC_M_Openacc1 openacc1, EC_M_Msg msg);
EC_Errno EC_M_decompile_openacc1(EC_M_Openacc1 *openacc1, EC_M_Msg msg);

typedef struct EC_M_Rsaenc_s {
    BIGNUM *key;
} * EC_M_Rsaenc;

EC_M_Rsaenc EC_M_new_rsaenc(BIGNUM *key);
EC_M_Rsaenc EC_M_clone_rsaenc(EC_M_Rsaenc rsaenc);
EC_Errno EC_M_examine_rsaenc(EC_M_Rsaenc rsaenc, BIGNUM **key);
UInt32 EC_M_cmp_rsaenc(EC_M_Rsaenc rsaenc1, EC_M_Rsaenc rsaenc2);
void EC_M_free_rsaenc(EC_M_Rsaenc rsaenc);
EC_Errno EC_M_compile_rsaenc(EC_M_Rsaenc rsaenc, EC_M_Msg msg);
EC_Errno EC_M_decompile_rsaenc(EC_M_Rsaenc *rsaenc, EC_M_Msg msg);

typedef struct EC_M_Encrypt_s {
    UInt32 algorithm;
    Byte *ivdata;
    UInt32 ivlen;
    UInt32 size;
    Byte *xdata;
    UInt32 xlen;
} * EC_M_Encrypt;

EC_M_Encrypt EC_M_new_encrypt(EC_M_Cryptalg algorithm, Byte *ivdata,
    UInt32 ivlen, UInt32 size, Byte *xdata, UInt32 xlen);
EC_M_Encrypt EC_M_clone_encrypt(EC_M_Encrypt encrypt);
EC_Errno EC_M_examine_encrypt(EC_M_Encrypt encrypt, EC_M_Cryptalg *algorithm,
    Byte **ivdata, UInt32 *ivlen, UInt32 *size, Byte **xdata, UInt32 *xlen);
UInt32 EC_M_cmp_encrypt(EC_M_Encrypt encrypt1, EC_M_Encrypt encrypt2);
void EC_M_free_encrypt(EC_M_Encrypt encrypt);
EC_Errno EC_M_compile_encrypt(EC_M_Encrypt encrypt, EC_M_Msg msg);
EC_Errno EC_M_decompile_encrypt(EC_M_Encrypt *encrypt, EC_M_Msg msg);

typedef struct EC_M_Bank_encr_s {
    UInt32 keyno;
    EC_M_Rsaenc rsaenc;
    EC_M_Encrypt encrypt;
} * EC_M_Bank_encr;

EC_M_Bank_encr EC_M_new_bank_encr(UInt32 keyno, EC_M_Rsaenc rsaenc,
    EC_M_Encrypt encrypt);
EC_M_Bank_encr EC_M_clone_bank_encr(EC_M_Bank_encr bank_encr);
EC_Errno EC_M_examine_bank_encr(EC_M_Bank_encr bank_encr, UInt32 *keyno,
    EC_M_Rsaenc *rsaenc, EC_M_Encrypt *encrypt);
UInt32 EC_M_cmp_bank_encr(EC_M_Bank_encr bank_encr1,
    EC_M_Bank_encr bank_encr2);
void EC_M_free_bank_encr(EC_M_Bank_encr bank_encr);
EC_Errno EC_M_compile_bank_encr(EC_M_Bank_encr bank_encr, EC_M_Msg msg);
EC_Errno EC_M_decompile_bank_encr(EC_M_Bank_encr *bank_encr, EC_M_Msg msg);

typedef struct EC_M_Openacc2_s {
    UInt32 userID;
    UInt32 msg_seq;
    BIGNUM *n;
    EC_M_Protocol protocol;
} * EC_M_Openacc2;

EC_M_Openacc2 EC_M_new_openacc2(UInt32 userID, UInt32 msg_seq,
    BIGNUM *n, EC_M_Protocol protocol);
EC_M_Openacc2 EC_M_clone_openacc2(EC_M_Openacc2 openacc2);
EC_Errno EC_M_examine_openacc2(EC_M_Openacc2 openacc2, UInt32 *userID,
    UInt32 *msg_seq, BIGNUM **n, UInt32 *protocol);
UInt32 EC_M_cmp_openacc2(EC_M_Openacc2 openacc21, EC_M_Openacc2 openacc22);
void EC_M_free_openacc2(EC_M_Openacc2 openacc2);
EC_Errno EC_M_compile_openacc2(EC_M_Openacc2 openacc2, EC_M_Msg msg);
EC_Errno EC_M_decompile_openacc2(EC_M_Openacc2 *openacc2, EC_M_Msg msg);

typedef struct EC_M_Bankhdr_s {
    UInt32 bankID;
    UInt32 keyno;
} * EC_M_Bankhdr;

EC_M_Bankhdr EC_M_new_bankhdr(UInt32 bankID, UInt32 keyno);
EC_M_Bankhdr EC_M_clone_bankhdr(EC_M_Bankhdr bankhdr);
EC_Errno EC_M_examine_bankhdr(EC_M_Bankhdr bankhdr, UInt32 *bankID,
    UInt32 *keyno);
UInt32 EC_M_cmp_bankhdr(EC_M_Bankhdr bankhdr1, EC_M_Bankhdr bankhdr2);
void EC_M_free_bankhdr(EC_M_Bankhdr bankhdr);
EC_Errno EC_M_compile_bankhdr(EC_M_Bankhdr bankhdr, EC_M_Msg msg);
EC_Errno EC_M_decompile_bankhdr(EC_M_Bankhdr *bankhdr, EC_M_Msg msg);

typedef struct EC_M_Bank_repl_s {
    UInt32 userID;
    UInt32 msg_seq;
    time_t reftime;
    time_t timestamp;
} * EC_M_Bank_repl;

EC_M_Bank_repl EC_M_new_bank_repl(UInt32 userID, UInt32 msg_seq,
    time_t reftime, time_t timestamp);
EC_M_Bank_repl EC_M_clone_bank_repl(EC_M_Bank_repl bank_repl);
EC_Errno EC_M_examine_bank_repl(EC_M_Bank_repl bank_repl, UInt32 *userID,
    UInt32 *msg_seq, time_t *reftime, time_t *timestamp);
UInt32 EC_M_cmp_bank_repl(EC_M_Bank_repl bank_repl1, EC_M_Bank_repl bank_repl2);
void EC_M_free_bank_repl(EC_M_Bank_repl bank_repl);
EC_Errno EC_M_compile_bank_repl(EC_M_Bank_repl bank_repl, EC_M_Msg msg);
EC_Errno EC_M_decompile_bank_repl(EC_M_Bank_repl *bank_repl, EC_M_Msg msg);

typedef struct EC_M_Cinfo_s {
    EC_M_Protocol protocol;
    UInt32 base_val;
    EC_M_Currency currency;
    UInt32 keyversion;
    time_t expire_time;
} * EC_M_Cinfo;

EC_M_Cinfo EC_M_new_cinfo(EC_M_Protocol protocol, UInt32 base_val,
    EC_M_Currency currency, UInt32 keyversion, time_t expire_time);
EC_M_Cinfo EC_M_clone_cinfo(EC_M_Cinfo cinfo);
EC_Errno EC_M_examine_cinfo(EC_M_Cinfo cinfo, EC_M_Protocol *protocol,
    UInt32 *base_val, EC_M_Currency *currency, UInt32 *keyversion,
    time_t *expire_time);
UInt32 EC_M_cmp_cinfo(EC_M_Cinfo cinfo1, EC_M_Cinfo cinfo2);
void EC_M_free_cinfo(EC_M_Cinfo cinfo);
EC_Errno EC_M_compile_cinfo(EC_M_Cinfo cinfo, EC_M_Msg msg);
EC_Errno EC_M_decompile_cinfo(EC_M_Cinfo *cinfo, EC_M_Msg msg);

typedef struct EC_M_Onl_curr_s {
    BIGNUM *coin_n;
    UInt32 ndenom;
    BIGNUM **coin_e;
    BIGNUM *seal_n;
    BIGNUM *seal_e;
} * EC_M_Onl_curr;

EC_M_Onl_curr EC_M_new_onl_curr(BIGNUM *coin_n, UInt32 ndenom,
    BIGNUM **coin_e, BIGNUM *seal_n, BIGNUM *seal_e);
EC_M_Onl_curr EC_M_clone_onl_curr(EC_M_Onl_curr onl_curr);
EC_Errno EC_M_examine_onl_curr(EC_M_Onl_curr onl_curr, BIGNUM **coin_n,
    UInt32 *ndenom, BIGNUM ***coin_e, BIGNUM **seal_n, BIGNUM **seal_e);
UInt32 EC_M_cmp_onl_curr(EC_M_Onl_curr onl_curr1, EC_M_Onl_curr onl_curr2);
void EC_M_free_onl_curr(EC_M_Onl_curr onl_curr);
EC_Errno EC_M_compile_onl_curr(EC_M_Onl_curr onl_curr, EC_M_Msg msg);
EC_Errno EC_M_decompile_onl_curr(EC_M_Onl_curr *onl_curr, EC_M_Msg msg);

typedef struct EC_M_Curr_s {
    UInt32 numcurrs;
    EC_M_Cinfo *cinfo;
    EC_M_Onl_curr *onl_curr;
} * EC_M_Curr;

EC_M_Curr EC_M_new_curr(UInt32 numcurrs, EC_M_Cinfo *cinfo,
    EC_M_Onl_curr *onl_curr);
EC_M_Curr EC_M_clone_curr(EC_M_Curr curr);
EC_Errno EC_M_examine_curr(EC_M_Curr curr, UInt32 *numcurrs,
    EC_M_Cinfo **cinfo, EC_M_Onl_curr **onl_curr);
UInt32 EC_M_cmp_curr(EC_M_Curr curr1, EC_M_Curr curr2);
void EC_M_free_curr(EC_M_Curr curr);
EC_Errno EC_M_compile_curr(EC_M_Curr curr, EC_M_Msg msg);
EC_Errno EC_M_decompile_curr(EC_M_Curr *curr, EC_M_Msg msg);

typedef struct EC_M_Error_s {
    EC_M_Errno errno;
} * EC_M_Error;

EC_M_Error EC_M_new_error(EC_M_Errno errno);
EC_M_Error EC_M_clone_error(EC_M_Error error);
EC_Errno EC_M_examine_error(EC_M_Error error, EC_M_Errno *errno);
UInt32 EC_M_cmp_error(EC_M_Error error1, EC_M_Error error2);
void EC_M_free_error(EC_M_Error error);
EC_Errno EC_M_compile_error(EC_M_Error error, EC_M_Msg msg);
EC_Errno EC_M_decompile_error(EC_M_Error *error, EC_M_Msg msg);

typedef struct EC_M_Userprivkey_s {
    BIGNUM *d;
    BIGNUM *q;
    BIGNUM *p;
    BIGNUM *iqmp;
} * EC_M_Userprivkey;

EC_M_Userprivkey EC_M_new_userprivkey(BIGNUM *d, BIGNUM *q, BIGNUM *p,
    BIGNUM *iqmp);
EC_M_Userprivkey EC_M_clone_userprivkey(EC_M_Userprivkey userprivkey);
EC_Errno EC_M_examine_userprivkey(EC_M_Userprivkey userprivkey, BIGNUM **d,
    BIGNUM **q, BIGNUM **p, BIGNUM **iqmp);
UInt32 EC_M_cmp_userprivkey(EC_M_Userprivkey userprivkey1,
    EC_M_Userprivkey userprivkey2);
void EC_M_free_userprivkey(EC_M_Userprivkey userprivkey);
EC_Errno EC_M_compile_userprivkey(EC_M_Userprivkey userprivkey, EC_M_Msg msg);
EC_Errno EC_M_decompile_userprivkey(EC_M_Userprivkey *userprivkey,
    EC_M_Msg msg);

typedef struct EC_M_Userkey_s {
    BIGNUM *n;
    BIGNUM *e;
    UInt32 keyno;
    EC_M_Encrypt privkey;
} * EC_M_Userkey;

EC_M_Userkey EC_M_new_userkey(BIGNUM *n, BIGNUM *e, UInt32 keyno,
    EC_M_Encrypt privkey);
EC_M_Userkey EC_M_clone_userkey(EC_M_Userkey userkey);
EC_Errno EC_M_examine_userkey(EC_M_Userkey userkey, BIGNUM **n,
    BIGNUM **e, UInt32 *keyno, EC_M_Encrypt *privkey);
UInt32 EC_M_cmp_userkey(EC_M_Userkey userkey1, EC_M_Userkey userkey2);
void EC_M_free_userkey(EC_M_Userkey userkey);
EC_Errno EC_M_compile_userkey(EC_M_Userkey userkey, EC_M_Msg msg);
EC_Errno EC_M_decompile_userkey(EC_M_Userkey *userkey, EC_M_Msg msg);

typedef struct EC_M_Userrec_s {
    UInt32 userID;
    EC_M_Userkey userkey;
    UInt32 bankID;
    EC_M_Currency currency;
    char *username;
} * EC_M_Userrec;

EC_M_Userrec EC_M_new_userrec(UInt32 userID, EC_M_Userkey userkey,
    UInt32 bankID, EC_M_Currency currency, char *username);
EC_M_Userrec EC_M_clone_userrec(EC_M_Userrec userrec);
EC_Errno EC_M_examine_userrec(EC_M_Userrec userrec, UInt32 *userID,
    EC_M_Userkey *userkey, UInt32 *bankID, EC_M_Currency *currency,
    char **username);
UInt32 EC_M_cmp_userrec(EC_M_Userrec userrec1, EC_M_Userrec userrec2);
void EC_M_free_userrec(EC_M_Userrec userrec);
EC_Errno EC_M_compile_userrec(EC_M_Userrec userrec, EC_M_Msg msg);
EC_Errno EC_M_decompile_userrec(EC_M_Userrec *userrec, EC_M_Msg msg);

typedef struct EC_M_Status_s {
    UInt32 msg_seq;
    UInt32 wd_seq;
    time_t nextstamp;
    UInt32 balance;
    UInt32 cash;
} * EC_M_Status;

EC_M_Status EC_M_new_status(UInt32 msg_seq, UInt32 wd_seq,
    time_t nextstamp, UInt32 balance, UInt32 cash);
EC_M_Status EC_M_clone_status(EC_M_Status status);
EC_Errno EC_M_examine_status(EC_M_Status status, UInt32 *msg_seq,
    UInt32 *wd_seq, time_t *nextstamp, UInt32 *balance, UInt32 *cash);
UInt32 EC_M_cmp_status(EC_M_Status status1, EC_M_Status status2);
void EC_M_free_status(EC_M_Status status);
EC_Errno EC_M_compile_status(EC_M_Status status, EC_M_Msg msg);
EC_Errno EC_M_decompile_status(EC_M_Status *status, EC_M_Msg msg);

typedef struct EC_M_Statement_s {
    UInt32 balance;
} * EC_M_Statement;

EC_M_Statement EC_M_new_statement(UInt32 balance);
EC_M_Statement EC_M_clone_statement(EC_M_Statement statement);
EC_Errno EC_M_examine_statement(EC_M_Statement statement, UInt32 *balance);
UInt32 EC_M_cmp_statement(EC_M_Statement statement1, EC_M_Statement statement2);
void EC_M_free_statement(EC_M_Statement statement);
EC_Errno EC_M_compile_statement(EC_M_Statement statement, EC_M_Msg msg);
EC_Errno EC_M_decompile_statement(EC_M_Statement *statement, EC_M_Msg msg);

typedef struct EC_M_Payment_hdr_s {
    UInt32 bankID;
    EC_M_Protocol protocol;
    UInt32 amount;
    EC_M_Currency currency;
    UInt32 ncoins;
    time_t timestamp;
    time_t expires;
    UInt32 shop_bankID;
    char *shop_accID;
    Byte *payer_hash;
    UInt32 payer_hashlen;
    Byte *descr_hash;
    UInt32 descr_hashlen;
    UInt32 flags;
    char *descr;
    char *comment;
    Byte *payer_code;
    UInt32 payer_codelen;
    UInt32 seqno;
    time_t rcv_time;
    UInt32 payment_version;
    Byte *snapdata;
    UInt32 snaplen;
} * EC_M_Payment_hdr;

EC_M_Payment_hdr EC_M_new_payment_hdr(UInt32 bankID, EC_M_Protocol protocol,
    UInt32 amount, EC_M_Currency currency, UInt32 ncoins, time_t timestamp,
    time_t expires, UInt32 shop_bankID, char *shop_accID, Byte *payer_hash,
    UInt32 payer_hashlen, Byte *descr_hash, UInt32 descr_hashlen,
    UInt32 flags, char *descr, char *comment, Byte *payer_code,
    UInt32 payer_codelen, UInt32 seqno, time_t rcv_time,
    UInt32 payment_version);
EC_M_Payment_hdr EC_M_clone_payment_hdr(EC_M_Payment_hdr payment_hdr);
EC_Errno EC_M_examine_payment_hdr(EC_M_Payment_hdr payment_hdr, UInt32 *bankID,
    EC_M_Protocol *protocol, UInt32 *amount, EC_M_Currency *currency,
    UInt32 *ncoins, time_t *timestamp, time_t *expires, UInt32 *shop_bankID,
    char **shop_accID, Byte **payer_hash, UInt32 *payer_hashlen,
    Byte **descr_hash, UInt32 *descr_hashlen, UInt32 *flags, char **descr,
    char **comment, Byte **payer_code, UInt32 *payer_codelen, UInt32 *seqno,
    time_t *rcv_time, UInt32 *payment_version, Byte **snapdata,
    UInt32 *snaplen);
UInt32 EC_M_cmp_payment_hdr(EC_M_Payment_hdr payment_hdr1,
    EC_M_Payment_hdr payment_hdr2);
void EC_M_free_payment_hdr(EC_M_Payment_hdr payment_hdr);
EC_Errno EC_M_compile_payment_hdr(EC_M_Payment_hdr payment_hdr, EC_M_Msg msg);
EC_Errno EC_M_decompile_payment_hdr(EC_M_Payment_hdr *payment_hdr,
    EC_M_Msg msg);
EC_Errno EC_M_snap_payment_hdr(EC_M_Payment_hdr payment_hdr);

typedef struct EC_M_Onl_coin_s {
    UInt32 keyversion;
    BIGNUM *n;
    BIGNUM *sig;
    UInt32 value;
} * EC_M_Onl_coin;

EC_M_Onl_coin EC_M_new_onl_coin(UInt32 keyversion, BIGNUM *n, BIGNUM *sig,
    UInt32 value);
EC_M_Onl_coin EC_M_clone_onl_coin(EC_M_Onl_coin onl_coin);
EC_Errno EC_M_examine_onl_coin(EC_M_Onl_coin onl_coin, UInt32 *keyversion,
    BIGNUM **n, BIGNUM **sig, UInt32 *value);
UInt32 EC_M_cmp_onl_coin(EC_M_Onl_coin onl_coin1, EC_M_Onl_coin onl_coin2);
void EC_M_free_onl_coin(EC_M_Onl_coin onl_coin);
EC_Errno EC_M_compile_onl_coin(EC_M_Onl_coin onl_coin, EC_M_Msg msg);
EC_Errno EC_M_decompile_onl_coin(EC_M_Onl_coin *onl_coin, EC_M_Msg msg);

typedef struct EC_M_Pcoins_s {
    UInt32 numcoins;
    EC_M_Onl_coin *onl_coin;
} * EC_M_Pcoins;

EC_M_Pcoins EC_M_new_pcoins(UInt32 numcoins, EC_M_Onl_coin *onl_coin);
EC_M_Pcoins EC_M_clone_pcoins(EC_M_Pcoins pcoins);
EC_Errno EC_M_examine_pcoins(EC_M_Pcoins pcoins, UInt32 *numcoins,
    EC_M_Onl_coin **onl_coin);
UInt32 EC_M_cmp_pcoins(EC_M_Pcoins pcoins1, EC_M_Pcoins pcoins2);
void EC_M_free_pcoins(EC_M_Pcoins pcoins);
EC_Errno EC_M_compile_pcoins(EC_M_Pcoins pcoins, EC_M_Msg msg);
EC_Errno EC_M_decompile_pcoins(EC_M_Pcoins *pcoins, EC_M_Msg msg);

typedef struct EC_M_Payment_s {
    EC_M_Payment_hdr payment_hdr;
    EC_M_Pcoins pcoins;
} * EC_M_Payment;

EC_M_Payment EC_M_new_payment(EC_M_Payment_hdr payment_hdr,
    EC_M_Pcoins pcoins);
EC_M_Payment EC_M_clone_payment(EC_M_Payment payment);
EC_Errno EC_M_examine_payment(EC_M_Payment payment,
    EC_M_Payment_hdr *payment_hdr, EC_M_Pcoins *pcoins);
UInt32 EC_M_cmp_payment(EC_M_Payment payment1, EC_M_Payment payment2);
void EC_M_free_payment(EC_M_Payment payment);
EC_Errno EC_M_compile_payment(EC_M_Payment payment, EC_M_Msg msg);
EC_Errno EC_M_decompile_payment(EC_M_Payment *payment, EC_M_Msg msg);

typedef struct EC_M_Dep_s {
    UInt32 seqno;
    EC_M_Payment_hdr payment_hdr;
    EC_M_Pcoins pcoins;
} * EC_M_Dep;

EC_M_Dep EC_M_new_dep(UInt32 seqno, EC_M_Payment_hdr payment_hdr,
    EC_M_Pcoins pcoins);
EC_M_Dep EC_M_clone_dep(EC_M_Dep dep);
EC_Errno EC_M_examine_dep(EC_M_Dep dep, UInt32 *seqno,
    EC_M_Payment_hdr *payment_hdr, EC_M_Pcoins *pcoins);
UInt32 EC_M_cmp_dep(EC_M_Dep dep1, EC_M_Dep dep2);
void EC_M_free_dep(EC_M_Dep dep);
EC_Errno EC_M_compile_dep(EC_M_Dep dep, EC_M_Msg msg);
EC_Errno EC_M_decompile_dep(EC_M_Dep *dep, EC_M_Msg msg);

typedef struct EC_M_Deposit_s {
    UInt32 numdeps;
    EC_M_Dep *dep;
} * EC_M_Deposit;

EC_M_Deposit EC_M_new_deposit(UInt32 numdeps, EC_M_Dep *dep);
EC_M_Deposit EC_M_clone_deposit(EC_M_Deposit deposit);
EC_Errno EC_M_examine_deposit(EC_M_Deposit deposit, UInt32 *numdeps,
    EC_M_Dep **dep);
UInt32 EC_M_cmp_deposit(EC_M_Deposit deposit1, EC_M_Deposit deposit2);
void EC_M_free_deposit(EC_M_Deposit deposit);
EC_Errno EC_M_compile_deposit(EC_M_Deposit deposit, EC_M_Msg msg);
EC_Errno EC_M_decompile_deposit(EC_M_Deposit *deposit, EC_M_Msg msg);

typedef struct EC_M_Dep_1ack_s {
    UInt32 seqno;
    UInt32 result;
    UInt32 amount;
} * EC_M_Dep_1ack;

EC_M_Dep_1ack EC_M_new_dep_1ack(UInt32 seqno, UInt32 result, UInt32 amount);
EC_M_Dep_1ack EC_M_clone_dep_1ack(EC_M_Dep_1ack dep_1ack);
EC_Errno EC_M_examine_dep_1ack(EC_M_Dep_1ack dep_1ack, UInt32 *seqno,
    UInt32 *result, UInt32 *amount);
UInt32 EC_M_cmp_dep_1ack(EC_M_Dep_1ack dep_1ack1, EC_M_Dep_1ack dep_1ack2);
void EC_M_free_dep_1ack(EC_M_Dep_1ack dep_1ack);
EC_Errno EC_M_compile_dep_1ack(EC_M_Dep_1ack dep_1ack, EC_M_Msg msg);
EC_Errno EC_M_decompile_dep_1ack(EC_M_Dep_1ack *dep_1ack, EC_M_Msg msg);

typedef struct EC_M_Dep_ack_s {
    UInt32 numacks;
    EC_M_Dep_1ack *dep_1ack;
} * EC_M_Dep_ack;

EC_M_Dep_ack EC_M_new_dep_ack(UInt32 numacks, EC_M_Dep_1ack *dep_1ack);
EC_M_Dep_ack EC_M_clone_dep_ack(EC_M_Dep_ack dep_ack);
EC_Errno EC_M_examine_dep_ack(EC_M_Dep_ack dep_ack, UInt32 *numacks,
    EC_M_Dep_1ack **dep_1ack);
UInt32 EC_M_cmp_dep_ack(EC_M_Dep_ack dep_ack1, EC_M_Dep_ack dep_ack2);
void EC_M_free_dep_ack(EC_M_Dep_ack dep_ack);
EC_Errno EC_M_compile_dep_ack(EC_M_Dep_ack dep_ack, EC_M_Msg msg);
EC_Errno EC_M_decompile_dep_ack(EC_M_Dep_ack *dep_ack, EC_M_Msg msg);

typedef struct EC_M_Userhdr_s {
    UInt32 userID;
    time_t timestamp;
    UInt32 bankID;
} * EC_M_Userhdr;

EC_M_Userhdr EC_M_new_userhdr(UInt32 userID, time_t timestamp, UInt32 bankID);
EC_M_Userhdr EC_M_clone_userhdr(EC_M_Userhdr userhdr);
EC_Errno EC_M_examine_userhdr(EC_M_Userhdr userhdr, UInt32 *userID,
    time_t *timestamp, UInt32 *bankID);
UInt32 EC_M_cmp_userhdr(EC_M_Userhdr userhdr1, EC_M_Userhdr userhdr2);
void EC_M_free_userhdr(EC_M_Userhdr userhdr);
EC_Errno EC_M_compile_userhdr(EC_M_Userhdr userhdr, EC_M_Msg msg);
EC_Errno EC_M_decompile_userhdr(EC_M_Userhdr *userhdr, EC_M_Msg msg);

typedef struct EC_M_Wdfin_s {
    UInt32 keyversion;
    UInt32 ncoins;
    UInt32 *seqno;
    BIGNUM **R;
} * EC_M_Wdfin;

EC_M_Wdfin EC_M_new_wdfin(UInt32 keyversion, UInt32 ncoins,
    UInt32 *seqno, BIGNUM **R);
EC_M_Wdfin EC_M_clone_wdfin(EC_M_Wdfin wdfin);
EC_Errno EC_M_examine_wdfin(EC_M_Wdfin wdfin, UInt32 *keyversion,
    UInt32 *ncoins, UInt32 **seqno, BIGNUM ***R);
UInt32 EC_M_cmp_wdfin(EC_M_Wdfin wdfin1, EC_M_Wdfin wdfin2);
void EC_M_free_wdfin(EC_M_Wdfin wdfin);
EC_Errno EC_M_compile_wdfin(EC_M_Wdfin wdfin, EC_M_Msg msg, UInt32 skip_wrap);
EC_Errno EC_M_decompile_wdfin(EC_M_Wdfin *wdfin, EC_M_Msg msg);

typedef struct EC_M_Withdraw3_s {
    EC_M_Protocol protocol;
    UInt32 flags;
    UInt32 total_coins;
    UInt32 numwds;
    EC_M_Wdfin *wdfin;
} * EC_M_Withdraw3;

EC_M_Withdraw3 EC_M_new_withdraw3(EC_M_Protocol protocol, UInt32 flags,
    UInt32 total_coins, UInt32 numwds, EC_M_Wdfin *wdfin);
EC_M_Withdraw3 EC_M_clone_withdraw3(EC_M_Withdraw3 withdraw3);
EC_Errno EC_M_examine_withdraw3(EC_M_Withdraw3 withdraw3,
    EC_M_Protocol *protocol, UInt32 *flags, UInt32 *total_coins,
    UInt32 *numwds, EC_M_Wdfin **wdfin);
UInt32 EC_M_cmp_withdraw3(EC_M_Withdraw3 withdraw31, EC_M_Withdraw3 withdraw32);
void EC_M_free_withdraw3(EC_M_Withdraw3 withdraw3);
EC_Errno EC_M_compile_withdraw3(EC_M_Withdraw3 withdraw3, EC_M_Msg msg);
EC_Errno EC_M_decompile_withdraw3(EC_M_Withdraw3 *withdraw3, EC_M_Msg msg);

typedef struct EC_M_Withdraw4_s {
    EC_M_Protocol protocol;
    UInt32 total_coins;
    UInt32 numwds;
    EC_M_Wdfin *wdfin;
} * EC_M_Withdraw4;

EC_M_Withdraw4 EC_M_new_withdraw4(EC_M_Protocol protocol,
    UInt32 total_coins, UInt32 numwds, EC_M_Wdfin *wdfin);
EC_M_Withdraw4 EC_M_clone_withdraw4(EC_M_Withdraw4 withdraw4);
EC_Errno EC_M_examine_withdraw4(EC_M_Withdraw4 withdraw4,
    EC_M_Protocol *protocol, UInt32 *total_coins,
    UInt32 *numwds, EC_M_Wdfin **wdfin);
UInt32 EC_M_cmp_withdraw4(EC_M_Withdraw4 withdraw41, EC_M_Withdraw4 withdraw42);
void EC_M_free_withdraw4(EC_M_Withdraw4 withdraw4);
EC_Errno EC_M_compile_withdraw4(EC_M_Withdraw4 withdraw4, EC_M_Msg msg);
EC_Errno EC_M_decompile_withdraw4(EC_M_Withdraw4 *withdraw4, EC_M_Msg msg);

typedef struct EC_M_Coindata_s {
    UInt32 seqno;
    UInt32 keyversion;
    BIGNUM *n;
    BIGNUM *fn;
    BIGNUM *r;
    BIGNUM *fnrh;
    BIGNUM *fn1hr;
    BIGNUM *fn1h;
    UInt32 paymentid;              /* Currently unused */
    struct EC_M_Coindata_s *next;  /* Used only in tallies */
} * EC_M_Coindata;

EC_M_Coindata EC_M_new_coindata(UInt32 seqno, UInt32 keyversion, BIGNUM *n,
    BIGNUM *fn, BIGNUM *r, BIGNUM *fnrh, BIGNUM *fn1hr, BIGNUM *fn1h,
    UInt32 paymentid);
EC_M_Coindata EC_M_clone_coindata(EC_M_Coindata coindata);
EC_Errno EC_M_examine_coindata(EC_M_Coindata coindata, UInt32 *seqno,
    UInt32 *keyversion, BIGNUM **n, BIGNUM **fn, BIGNUM **r, BIGNUM **fnrh,
    BIGNUM **fn1hr, BIGNUM **fn1h, UInt32 *paymentid);
UInt32 EC_M_cmp_coindata(EC_M_Coindata coindata1, EC_M_Coindata coindata2);
void EC_M_free_coindata(EC_M_Coindata coindata);
EC_Errno EC_M_compile_coindata(EC_M_Coindata coindata, EC_M_Msg msg);
EC_Errno EC_M_decompile_coindata(EC_M_Coindata *coindata, EC_M_Msg msg);

typedef struct EC_M_Payreq_s {
    EC_M_Currency currency;
    UInt32 amount;
    time_t timestamp;
    UInt32 shop_bankID;
    char *shop_accID;
    char *descr;
    char *conn_host;
    UInt32 conn_port;
} * EC_M_Payreq;

EC_M_Payreq EC_M_new_payreq(EC_M_Currency currency, UInt32 amount,
    time_t timestamp, UInt32 shop_bankID, char *shop_accID, char *descr,
    char *conn_host, UInt32 conn_port);
EC_M_Payreq EC_M_clone_payreq(EC_M_Payreq payreq);
EC_Errno EC_M_examine_payreq(EC_M_Payreq payreq, EC_M_Currency *currency,
    UInt32 *amount, time_t *timestamp, UInt32 *shop_bankID, char **shop_accID,
    char **descr, char **conn_host, UInt32 *conn_port);
UInt32 EC_M_cmp_payreq(EC_M_Payreq payreq1, EC_M_Payreq payreq2);
void EC_M_free_payreq(EC_M_Payreq payreq);
EC_Errno EC_M_compile_payreq(EC_M_Payreq payreq, EC_M_Msg msg);
EC_Errno EC_M_decompile_payreq(EC_M_Payreq *payreq, EC_M_Msg msg);

/* Encoding functions */

EC_Errno EC_M_ATE_encode(EC_M_Msg msg, char *title, char *headers,
    Int32 (*output_fcn)(Byte *outdata, UInt32 outlen, void *state),
    void *state);

EC_Errno EC_M_BTE_encode(EC_M_Msg msg,
    Int32 (*output_fcn)(Byte *outdata, UInt32 outlen, void *state),
    void *state);

EC_Errno EC_M_BTE_decode(EC_M_Msg msg,
    Int32 (*input_fcn)(Byte *indata, UInt32 inlen, void *state),
    void *state);

EC_Errno EC_M_ATE_decode(EC_M_Msg msg,
    Int32 (*input_fcn)(Byte *indata, UInt32 inlen, void *state),
    void *state);

/* Utility functions */

/* Signature utilities */
BIGNUM *EC_U_str2bn(const char *s, int len);
BIGNUM *EC_U_f(Byte hashID, Byte *s, UInt32 len, BIGNUM *mod);
Int32 EC_U_verify_sigmsg(EC_M_Sigmsg sigmsg, BIGNUM *n, BIGNUM *e);
EC_M_Sigmsg EC_U_sign_sigmsg(BIGNUM *n, BIGNUM *d, EC_M_Msg msg);
EC_Errno EC_U_xor_MPI(BIGNUM *n, BIGNUM *xor);

/* Encryption utilities */
EC_M_Encrypt EC_U_encrypt_msg(EC_M_Cryptalg algorithm, Byte *key, UInt32 keylen,
    EC_M_Msg msg);
EC_M_Bank_encr EC_U_rsa_encrypt_msg(EC_M_Cryptalg algorithm, UInt32 keyno,
    BIGNUM *n, BIGNUM *e, EC_M_Msg msg);
EC_M_Msg EC_U_decrypt_msg(Byte *key, UInt32 keylen, EC_M_Encrypt encrypt);
EC_M_Msg EC_U_rsa_decrypt_msg(BIGNUM *n, BIGNUM *d, EC_M_Bank_encr bank_encr);
EC_Errno EC_U_pass2key(EC_M_Cryptalg algorithm, char *passphrase,
    Byte **pkey, UInt32 *pkeylen);

/* Protocol functions */
EC_Errno EC_P_create_setup_req(time_t stamp, EC_M_Msg msg);
EC_Errno EC_P_parse_setup(EC_M_Msg msg, BIGNUM *setup_n, BIGNUM *setup_e,
    EC_M_Bank_mkey *bank_mkey, char **bankname, EC_M_Protocols *protocols,
    EC_M_Error *error);

EC_Errno EC_P_parse_bankhdr(EC_M_Msg msg,
    EC_M_Bank_mkey (*find_mkey)(UInt32 bankID, UInt32 keyno, void *state),
    void *state, EC_M_Bank_repl *bank_repl, EC_M_Msg *submsg,
    EC_M_Error *error);

EC_Errno EC_P_create_openacc1(char *accID, EC_M_Currency currency, BIGNUM *acc_n,
    BIGNUM *acc_e, EC_M_Protocol protocol, char *password,
    EC_M_Bank_mkey bank_mkey, time_t stamp, EC_M_Msg msg);

EC_Errno EC_P_create_deposit(UInt32 numdeps, EC_M_Dep *givendep,
    EC_M_Userrec userrec, EC_M_Bank_mkey bank_mkey, time_t stamp,
    EC_M_Msg msg);

/* Types of locks */
typedef enum {
	EC_W_LOCK_READ = 0,
	EC_W_LOCK_WRITE = 1,
	EC_W_LOCK_READ_NOWAIT = 2,
	EC_W_LOCK_WRITE_NOWAIT = 3,
	EC_W_LOCK_UNLOCK = 4,
} EC_W_Locktype;

/* Definitions for the DB routines */
typedef DB * EC_W_Db;

/* Wallet functions */
typedef struct EC_W_Wallet_s {
	char *name;
	int lockfd;
	EC_W_Locktype locktype;
	char *passphrase;
	EC_M_Userrec userrec;
	EC_M_Userprivkey userprivkey;
	EC_M_Bank_mkey bkey_cache;
	EC_M_Curr curr_cache;
} * EC_W_Wallet;

/* Constants for the wallet */
#define EC_W_WALLET_DEFNAME ".ecwallet"
#define EC_W_LOCKFILE ".lock-lucre"
#define EC_W_USERFNAME "user"
#define EC_W_BKEYFNAME "bankkeys"
#define EC_W_CURRFNAME "currkeys"
#define EC_W_STATUSFNAME "status"
#define EC_W_RECDBFNAME "received.db"
#define EC_W_PAYDBFNAME "payments.db"
#define EC_W_WDDBFNAME "wdpending.db"
#define EC_W_CASHDBFNAME "cash"

#ifndef SPOOK_SAFE
#define EC_W_USER_CRYPTALG EC_M_CRYPTALG_112_3DES
#else
#define EC_W_USER_CRYPTALG EC_M_CRYPTALG_NONE
#endif /* SPOOK_SAFE */

EC_W_Wallet EC_W_wallet_open(char *walletid);
EC_Errno EC_W_wallet_usephrase(EC_W_Wallet wallet, char *passphrase);
EC_Errno EC_W_wallet_setphrase(EC_W_Wallet wallet, char *passphrase);
void EC_W_wallet_close(EC_W_Wallet wallet);
char *EC_W_wallet_getname(char *walletid);
char *EC_W_wallet_mkfname(char *walletname, char *filename, char *ext);
EC_Errno EC_W_wallet_lockfd(int lockfd, EC_W_Locktype locktype);
EC_Errno EC_W_wallet_lock(EC_W_Wallet wallet, EC_W_Locktype locktype);
EC_Errno EC_W_wallet_unlock(EC_W_Wallet wallet);
EC_W_Locktype EC_W_wallet_get_locktype(EC_W_Wallet wallet);
EC_Errno EC_W_wallet_templock(EC_W_Wallet wallet, EC_W_Locktype locktype,
    EC_W_Locktype *oldlock);

EC_Errno EC_W_user_create(char *walletname, char *passphrase,
    Int16 keybits, UInt32 e_value, void (*callback)(int, int));
EC_M_Userrec EC_W_user_read(char *walletname);
EC_Errno EC_W_user_write(EC_W_Wallet wallet);

EC_M_Status EC_W_status_read(EC_W_Wallet wallet);
EC_Errno EC_W_status_write(EC_W_Wallet wallet, EC_M_Status status);

EC_M_Bank_mkey EC_W_bankkeys_lookup(EC_W_Wallet wallet, UInt32 bankID,
    UInt32 keynumber);
EC_Errno EC_W_bankkeys_write(EC_W_Wallet wallet, EC_M_Bank_mkey bank_mkey);
EC_M_Bank_mkey EC_W_find_mkey(UInt32 bankID, UInt32 keynumber, void *state);

EC_M_Curr EC_W_curr_lookup(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, UInt32 keyversion);
EC_Errno EC_W_curr_write(EC_W_Wallet wallet, UInt32 bankID, EC_M_Curr curr);

EC_Errno EC_W_wallet_create_1(EC_W_Wallet *pwallet, EC_M_Msg msg,
    char *walletid, char *passphrase, void (*callback)(int, int));
EC_Errno EC_W_wallet_create_2(EC_W_Wallet *pwallet, EC_M_Msg msg,
    char *accID, EC_M_Currency currency, char *account_password,
    BIGNUM *setup_n, BIGNUM *setup_e);
EC_Errno EC_W_wallet_create_3(EC_W_Wallet *pwallet, EC_M_Msg msg);
void EC_W_wallet_create_abort(EC_W_Wallet *pwallet);

EC_Errno EC_W_deposit_all_payments_1(EC_W_Wallet wallet, EC_M_Msg msg,
    UInt32 *pnumdeps);
EC_Errno EC_W_deposit_all_payments_2(EC_W_Wallet wallet, EC_M_Msg msg,
    EC_M_Dep_ack *pdep_ack);
EC_Errno EC_W_deposit_payment_1(EC_W_Wallet wallet, EC_M_Msg msg,
    UInt32 seqno);
EC_Errno EC_W_deposit_payment_2(EC_W_Wallet wallet, EC_M_Msg msg,
    UInt32 seqno, UInt32 *paccepted, UInt32 *pamount);

EC_Errno EC_W_handle_common(EC_W_Wallet wallet, EC_M_Msg msg);
EC_Errno EC_W_handle_error(EC_W_Wallet wallet, EC_M_Error error);
EC_Errno EC_W_handle_bank_repl(EC_W_Wallet wallet, EC_M_Bank_repl bank_repl);
EC_Errno EC_W_statement_write(EC_W_Wallet wallet, EC_M_Statement statement);
time_t EC_W_timestamp(EC_W_Wallet wallet);

EC_W_Db EC_W_db_open(EC_W_Wallet wallet, char *dbname, int flags);
Int32 EC_W_db_close(EC_W_Db db);
Int32 EC_W_db_del(EC_W_Db db, EC_M_Msg key);
Int32 EC_W_db_get(EC_W_Db db, EC_M_Msg key, EC_M_Msg *data);
Int32 EC_W_db_put(EC_W_Db db, EC_M_Msg key, EC_M_Msg data);
Int32 EC_W_db_sync(EC_W_Db db);
Int32 EC_W_db_seq(EC_W_Db db, EC_M_Msg *key, EC_M_Msg *data);

EC_Errno EC_W_recdb_put(EC_W_Wallet wallet, EC_M_Payment payment,
    UInt32 *seqno);
EC_M_Dep EC_W_recdb_get(EC_W_Wallet wallet, UInt32 seqno);
EC_Errno EC_W_recdb_del(EC_W_Wallet wallet, EC_M_Dep_ack dep_ack);
EC_Errno EC_W_recdb_get_all(EC_W_Wallet wallet, EC_M_Dep **pdep,
    UInt32 *pnumdeps);

EC_Errno EC_W_paydb_put(EC_W_Wallet wallet, EC_M_Payment payment,
    UInt32 *pseqno);
EC_M_Payment EC_W_paydb_get(EC_W_Wallet wallet, UInt32 seqno);
EC_Errno EC_W_paydb_del(EC_W_Wallet wallet, UInt32 seqno);
EC_Errno EC_W_paydb_get_all(EC_W_Wallet wallet, EC_M_Payment **ppayment,
    UInt32 *pnumpayments);

typedef struct EC_W_Tally_s {
    UInt32 numvers;
    struct EC_W_Tally1_s {
	UInt32 keyversion;
	UInt32 ndenom;
	UInt32 *ncoins;
	EC_M_Coindata *coindata;
    } * ver;
} * EC_W_Tally;

typedef enum {
    EC_W_TALLY_NONE = 0,
    EC_W_TALLY_ONEDENOM = 1,
    EC_W_TALLY_MERGECVER = 2,
    EC_W_TALLY_MERGEDENOM = 4,
    EC_W_TALLY_INCOMPLETE = 8,
    EC_W_TALLY_PAID = 16,
    EC_W_TALLY_VERBOSE = 32,
} EC_W_Tallyflags;

EC_W_Tally EC_W_new_tally(void);
void EC_W_clear_tally(EC_W_Tally tally);
void EC_W_free_tally(EC_W_Tally tally);
EC_Errno EC_W_tally_inc(EC_W_Tally, UInt32 keyversion, Int32 amt,
    EC_W_Tallyflags flags);
EC_Errno EC_W_tally_inc_coin(EC_W_Tally, UInt32 keyversion, Int32 amt,
    EC_W_Tallyflags flags, EC_M_Coindata coindata);
UInt32 EC_W_tally_value(EC_W_Tally tally, UInt32 *pncoins);
EC_Errno EC_W_tally_inscoin(EC_M_Coindata *head, EC_M_Coindata coindata);

EC_M_Coindata EC_W_cashdb_gencoin(UInt32 bankID, EC_M_Onl_curr onl_curr,
    UInt32 keyversion, UInt32 seqno);
EC_Errno EC_W_cashdb_newcoin(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Curr curr, UInt32 keyversion, BIGNUM **pfnrh, UInt32 *pseqno);
EC_Errno EC_W_cashdb_finish(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, EC_M_Wdfin wdfin, UInt32 *pamt);
EC_Errno EC_W_cashdb_clean(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, EC_M_Wdfin wdfin);
EC_Errno EC_W_cashdb_del(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, EC_M_Coindata coindata);
EC_Errno EC_W_cashdb_tally(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, UInt32 keyversion, EC_W_Tallyflags tallyflags,
        EC_W_Tally tally);

EC_Errno EC_W_wddb_put(EC_W_Wallet wallet, EC_M_Msg wdmsg,
    time_t stamp);
EC_M_Msg EC_W_wddb_get(EC_W_Wallet wallet, time_t stamp);
EC_Errno EC_W_wddb_del(EC_W_Wallet wallet, time_t stamp);
EC_Errno EC_W_wddb_get_all(EC_W_Wallet wallet, time_t **pstamp,
    UInt32 *pnumstamps);

EC_Errno EC_W_withdraw_1(EC_W_Wallet wallet, EC_M_Msg msg, UInt32 amount,
    UInt32 minpayments);
EC_Errno EC_W_withdraw_old_1(EC_W_Wallet wallet, EC_M_Msg msg, time_t stamp);
EC_Errno EC_W_withdraw_2(EC_W_Wallet wallet, EC_M_Msg msg, UInt32 *pamount);

#define EC_W_PAYMENT_EXPTIME (14*60*3600)

EC_Errno EC_W_create_payment(EC_W_Wallet wallet, UInt32 amount,
    EC_M_Currency currency, char *shop, UInt32 shop_bankID, char *descr,
    UInt32 *pseqno);
EC_Errno EC_W_make_payment(EC_W_Wallet wallet, EC_M_Msg msg, UInt32 seqno);
EC_Errno EC_W_request_payment(EC_M_Msg msg, EC_M_Currency currency,
    UInt32 amount, UInt32 shop_bankID, char *shop_accID, char *descr,
    char *conn_host, UInt32 conn_port);

#endif

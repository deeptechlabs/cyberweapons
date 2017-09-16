/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- headers.h ------------------------------ */

#define HEADER_STRING_BEGIN "-----BEGIN PRIVACY-ENHANCED MESSAGE-----"
#define HEADER_STRING_BEGIN_LEN 40
#define HEADER_STRING_END   "-----END PRIVACY-ENHANCED MESSAGE-----"
#define HEADER_STRING_END_LEN 38
#define PUB_KEY_STRING_BEGIN    "-----BEGIN PUBLIC KEY-----"
#define PUB_KEY_STRING_BEGIN_LEN 26
#define PUB_KEY_STRING_END      "-----END PUBLIC KEY-----"
#define PUB_KEY_STRING_END_LEN 24
#define PRIV_KEY_STRING_BEGIN   "-----BEGIN PRIVATE KEY-----"
#define PRIV_KEY_STRING_BEGIN_LEN 27
#define PRIV_KEY_STRING_END     "-----END PRIVATE KEY-----"
#define PRIV_KEY_STRING_END_LEN 25

#define PROC_TYPE_FIELD         "Proc-Type:"
#define CONTENT_DOMAIN_FIELD    "Content-Domain:"
#define DEK_FIELD               "DEK-Info:"
#define SENDER_FIELD            "Originator-Name:"
#define SENDER_PUB_KEY_FIELD    "Originator-Key-Asymmetric:"
#define ORIGINATOR_CERT_FIELD   "Originator-Certificate:"
#define ISSUER_CERT_FIELD       "Issuer-Certificate:"
#define RECIPIENT_FIELD         "Recipient-Name:"
#define RECIPIENT_KEY_FIELD     "Recipient-Key-Asymmetric:"
#define RECIPIENT_ID_ASYMMETRIC_FIELD "Recipient-ID-Asymmetric:"
#define MESSAGE_KEY_FIELD       "Key-Info:"
#define MIC_INFO_FIELD          "MIC-Info:"
#define ISSUER_FIELD            "Issuer:"
#define CRL_FIELD               "CRL:"
#define UNREC_FIELD             NULL

#define PROC_TYPE_ENCRYPTED_ID  "ENCRYPTED"
#define PROC_TYPE_MIC_ONLY_ID   "MIC-ONLY"
#define PROC_TYPE_MIC_CLEAR_ID  "MIC-CLEAR"
#define PROC_TYPE_CRL_ID  "CRL"
#define PROC_TYPE_CRL_REQUEST_ID  "CRL-RETRIEVAL-REQUEST"
#define MIC_MD2_ID              "RSA-MD2"
#define MIC_MD5_ID              "RSA-MD5"
#define MIC_SHA1_ID             "SHA1"
#define ENCRYPTION_ALG_RSA_ID   "RSA"
#define PROC_TYPE_RIPEM_ID      "2001"
#define PROC_TYPE_PEM_ID        "4"
#define DEK_ALG_DES_CBC_ID      "DES-CBC"
#define DEK_ALG_TDES_CBC_ID     "DES-EDE-CBC"
#define UNREC_ID                NULL

#define SPEC_SEP                ","


#define DEF_FIELDS(mac) \
        mac(PROC_TYPE),mac(CONTENT_DOMAIN),mac(DEK),mac(SENDER),     \
        mac(SENDER_PUB_KEY),mac(ORIGINATOR_CERT),mac(ISSUER_CERT),  \
        mac(RECIPIENT),mac(RECIPIENT_KEY),mac(RECIPIENT_ID_ASYMMETRIC), \
        mac(MESSAGE_KEY),mac(MIC_INFO),mac(ISSUER),mac(CRL),mac(UNREC)

#define DEF_IDS(mac) \
        mac(PROC_TYPE_ENCRYPTED_ID),   \
        mac(PROC_TYPE_MIC_ONLY_ID),    \
        mac(PROC_TYPE_MIC_CLEAR_ID),       \
        mac(PROC_TYPE_CRL_ID),       \
        mac(PROC_TYPE_CRL_REQUEST_ID),       \
        mac(MIC_MD2_ID),               \
        mac(MIC_MD5_ID),               \
        mac(MIC_SHA1_ID),               \
        mac(ENCRYPTION_ALG_RSA_ID),    \
        mac(PROC_TYPE_RIPEM_ID),       \
        mac(PROC_TYPE_PEM_ID),       \
        mac(DEK_ALG_DES_CBC_ID),       \
        mac(DEK_ALG_TDES_CBC_ID),       \
        mac(UNREC_ID)

#ifdef __STDC__
#define MAKE_ENUM(val) val##_ENUM
#define MAKE_TEXT(val) val##_FIELD
#define MAKE_IDS(val)  val
#else
#define MAKE_ENUM(val) val/**/_ENUM
#define MAKE_TEXT(val) val/**/_FIELD
#define MAKE_IDS(val)  val
#endif

enum enum_fields { DEF_FIELDS(MAKE_ENUM) };
enum enum_ids { DEF_IDS(MAKE_ENUM) };

extern char *FieldNames[];
extern char *IDNames[];

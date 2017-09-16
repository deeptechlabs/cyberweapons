#ifndef _CAPI_DEFINED

#define _CAPI_DEFINED

/* Fixup for Windows support.  We need to include windows.h for various types
   and prototypes needed for DLL's */

#if defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define WIN32_LEAN_AND_MEAN		/* Skip RPC, OLE, Multimedia, etc */
  #include <windows.h>
#endif /* _WINDOWS || WIN32 || _WIN32 */

/* Machine-dependant types to allow use in special library types such as
   DLL's.  Under Win32 we need to use the dllimport and dllexport directives
   for the DLL version of the library, so we define the type used for
   functions depending on whether we're being included via crypt.h or not */

#if ( defined( WIN32 ) || defined( _WIN32 ) ) && !defined( STATIC_LIB )
  #define CPTR	*					/* General pointer */
  #ifdef _CRYPT_DEFINED
	#define CRET	__declspec( dllexport ) int	__stdcall	/* DLL export ret.val.*/
  #else
	#define CRET	__declspec( dllimport ) int	__stdcall	/* DLL import ret.val.*/
  #endif /* CRYPT_DEFINED */
#elif defined( _WINDOWS )
  #define CPTR	FAR *				/* DLL pointer */
  #define CRET	int FAR PASCAL _export	/* DLL return value */
#else
  #define CPTR	*					/* General pointer */
  #define CRET	int					/* General return value */
#endif /* _WINDOWS && !( WIN32 || _WIN32 ) */

/****************************************************************************
*																			*
*							Algorithm and Object Constants					*
*																			*
****************************************************************************/

/* The encryption algorithms we can use */

typedef enum {
	/* No encryption */
	CRYPT_ALGO_NONE,				/* No encryption */

	/* Conventional encryption */
	CRYPT_ALGO_DES,					/* DES */
	CRYPT_ALGO_3DES,				/* Triple DES */
	CRYPT_ALGO_IDEA,				/* IDEA */
	CRYPT_ALGO_CAST,				/* CAST-128 */
	CRYPT_ALGO_RC2,					/* RC2 */
	CRYPT_ALGO_RC4,					/* RC4 */
	CRYPT_ALGO_RC5,					/* RC5 */
	CRYPT_ALGO_SAFER,				/* SAFER/SAFER-SK */
	CRYPT_ALGO_BLOWFISH,			/* Blowfish */
	CRYPT_ALGO_SKIPJACK,			/* Skipjack */
	CRYPT_ALGO_GOST,				/* GOST 28147 (not implemented yet) */

	/* Public-key encryption */
	CRYPT_ALGO_DH = 100,			/* Diffie-Hellman */
	CRYPT_ALGO_RSA,					/* RSA */
	CRYPT_ALGO_DSA,					/* DSA */
	CRYPT_ALGO_ELGAMAL,				/* ElGamal */

	/* Hash algorithms */
	CRYPT_ALGO_MD2 = 200,			/* MD2 */
	CRYPT_ALGO_MD4,					/* MD4 */
	CRYPT_ALGO_MD5,					/* MD5 */
	CRYPT_ALGO_SHA,					/* SHA/SHA1 */
	CRYPT_ALGO_RIPEMD160,			/* RIPE-MD 160 */
	CRYPT_ALGO_MDC2,				/* MDC-2 */

	/* MAC's */
	CRYPT_ALGO_HMAC_MD5 = 300,		/* HMAC-MD5 */
	CRYPT_ALGO_HMAC_SHA,			/* HMAC-SHA */
	CRYPT_ALGO_HMAC_RIPEMD160,		/* HMAC-RIPEMD-160 */

	/* Vendors may want to use their own algorithms which aren't part of the
	   general cryptlib suite.  The following values are for vendor-defined
	   algorithms, and can be used just like the named algorithm types (it's
	   up to the vendor to keep track of what _VENDOR1 actually corresponds
	   to) */
#ifdef USE_VENDOR_ALGOS
	CRYPT_ALGO_VENDOR1 = 10000, CRYPT_ALGO_VENDOR2, CRYPT_ALGO_VENDOR3,
#endif /* USE_VENDOR_ALGOS */

	CRYPT_ALGO_LAST,				/* Last possible crypt algo value */

	/* In order that we can scan through a range of algorithms with
	   cryptAlgoAvailable(), we define the following boundary points for each
	   algorithm class */
	CRYPT_ALGO_FIRST_CONVENTIONAL = CRYPT_ALGO_DES,
	CRYPT_ALGO_LAST_CONVENTIONAL = CRYPT_ALGO_DH - 1,
	CRYPT_ALGO_FIRST_PKC = CRYPT_ALGO_DH,
	CRYPT_ALGO_LAST_PKC = CRYPT_ALGO_MD2 - 1,
	CRYPT_ALGO_FIRST_HASH = CRYPT_ALGO_MD2,
	CRYPT_ALGO_LAST_HASH = CRYPT_ALGO_HMAC_MD5 - 1,
	CRYPT_ALGO_FIRST_MAC = CRYPT_ALGO_HMAC_MD5,
	CRYPT_ALGO_LAST_MAC = CRYPT_ALGO_HMAC_MD5 + 99	/* End of mac algo.range */
	} CRYPT_ALGO;

/* The encryption modes we can use */

typedef enum {
	/* No encryption */
	CRYPT_MODE_NONE,				/* No encryption (hashes and MAC's) */

	/* Stream cipher modes */
	CRYPT_MODE_STREAM,				/* Stream cipher */

	/* Block cipher modes */
	CRYPT_MODE_ECB,					/* ECB */
	CRYPT_MODE_CBC,					/* CBC */
	CRYPT_MODE_CFB,					/* CFB */
	CRYPT_MODE_OFB,					/* OFB */

	/* Public-key cipher modes */
	CRYPT_MODE_PKC = 100,			/* PKC */

	CRYPT_MODE_LAST,				/* Last possible crypt mode value */

	/* In order that we can scan through a range of modes with
	   cryptAlgoModeAvailable(), we define the following boundary points for
	   the conventional encryption modes */
	CRYPT_MODE_FIRST_CONVENTIONAL = CRYPT_MODE_STREAM,
	CRYPT_MODE_LAST_CONVENTIONAL = CRYPT_MODE_PKC - 1
	} CRYPT_MODE;

/* The encryption object types */

typedef enum {
	CRYPT_OBJECT_NONE,				/* No object type */
	CRYPT_OBJECT_ENCRYPTED_KEY,		/* Conventionally encrypted key */
	CRYPT_OBJECT_PKCENCRYPTED_KEY,	/* PKC-encrypted key */
	CRYPT_OBJECT_KEYAGREEMENT,		/* Key agreement information */
	CRYPT_OBJECT_SIGNATURE,			/* Signature */
	CRYPT_OBJECT_LAST				/* Last possible object type */
	} CRYPT_OBJECT_TYPE;

/* The keyset types */

typedef enum {
	CRYPT_KEYSET_NONE,				/* No keyset type */
	CRYPT_KEYSET_FILE,				/* Generic flat file keyset (PGP, X.509) */
	CRYPT_KEYSET_HTTP,				/* Web page containing cert/CRL */
	CRYPT_KEYSET_LDAP,				/* LDAP directory service */
	CRYPT_KEYSET_SMARTCARD,			/* Smart card key carrier */
	CRYPT_KEYSET_ODBC,				/* Generic ODBC interface */
	CRYPT_KEYSET_BSQL,				/* BSQL RDBMS */
	CRYPT_KEYSET_MSQL,				/* mSQL RDBMS */
	CRYPT_KEYSET_MYSQL,				/* MySQL RDBMS */
	CRYPT_KEYSET_ORACLE,			/* Oracle RDBMS */
	CRYPT_KEYSET_POSTGRES,			/* Postgres RDBMS */
	CRYPT_KEYSET_RAIMA,				/* Raima Velocis RDBMS */
	CRYPT_KEYSET_SOLID,				/* Solid RDBMS */
	CRYPT_KEYSET_LAST,				/* Last possible keyset type */

	/* Useful defines used internally for range checking */
	CRYPT_FIRST_RDBMS = CRYPT_KEYSET_ODBC,
	CRYPT_LAST_RDBMS = CRYPT_KEYSET_LAST - 1
	} CRYPT_KEYSET_TYPE;

/* The crypto device types */

typedef enum {
	CRYPT_DEVICE_NONE,				/* No crypto device */
	CRYPT_DEVICE_CEI,				/* CE Infosys DES/3DES crypto card */
	CRYPT_DEVICE_FORTEZZA,			/* Fortezza card */
	CRYPT_DEVICE_PKCS11,			/* PKCS #11 crypto token */
	CRYPT_DEVICE_SMARTCARD,			/* Cryptographic smart card */
	CRYPT_DEVICE_LAST				/* Last possible crypto device type */
	} CRYPT_DEVICE_TYPE;

/* The certificate object types */

typedef enum {
	CRYPT_CERTTYPE_NONE,			/* No certificate type */
	CRYPT_CERTTYPE_CERTIFICATE,		/* Certificate */
	CRYPT_CERTTYPE_ATTRIBUTE_CERT,	/* Attribute certificate */
	CRYPT_CERTTYPE_CERTCHAIN,		/* PKCS #7 certificate chain */
	CRYPT_CERTTYPE_CERTREQUEST,		/* PKCS #10 certification request */
	CRYPT_CERTTYPE_CRL,				/* CRL */
	CRYPT_CERTTYPE_OCSP_REQUEST,	/* OCSP request */
	CRYPT_CERTTYPE_OCSP_RESPONSE,	/* OCSP response */
	CRYPT_CERTTYPE_CMS_ATTRIBUTES,	/* CMS attributes */
	CRYPT_CERTTYPE_LAST				/* Last possible cert.type */
	} CRYPT_CERTTYPE_TYPE;

/* The certificate export format type, which defines the format in which a
   certificate object is exported */

typedef enum {
	CRYPT_CERTFORMAT_NONE,			/* No certificate format */
	CRYPT_CERTFORMAT_CERTIFICATE,	/* DER-encoded certificate */
	CRYPT_CERTFORMAT_CERTCHAIN,		/* PKCS #7 certificate chain */
	CRYPT_CERTFORMAT_NS_CERTSEQUENCE,	/* Netscape cert.sequence */
	CRYPT_CERTFORMAT_TEXT_CERTIFICATE,	/* base-64 wrapped cert */
	CRYPT_CERTFORMAT_TEXT_CERTCHAIN,	/* base-64 wrapped cert chain */
	CRYPT_CERTFORMAT_TEXT_NS_CERTSEQUENCE,	/* base-64 wrapped NS cert seq.*/
	CRYPT_CERTFORMAT_SMIME_CERTIFICATE,	/* S/MIME cert.request or cert chain */
	CRYPT_CERTFORMAT_LAST			/* Last possible cert.format type */
	} CRYPT_CERTFORMAT_TYPE;

/* Key ID types */

typedef enum {
	CRYPT_KEYID_NONE,				/* No key ID type */
	CRYPT_KEYID_NAME,				/* Key owner name */
	CRYPT_KEYID_EMAIL,				/* Key owner email address */
	CRYPT_KEYID_OBJECT,				/* Encryption object which requires key */
	CRYPT_KEYID_LAST				/* Last possible key ID type */
	} CRYPT_KEYID_TYPE;

/* Data format types */

typedef enum {
	CRYPT_FORMAT_NONE,				/* No format type */
	CRYPT_FORMAT_CRYPTLIB,			/* cryptlib native format */
	CRYPT_FORMAT_CMS,				/* PKCS #7 / CMS / S/MIME format */
		CRYPT_FORMAT_PKCS7 = CRYPT_FORMAT_CMS,
	CRYPT_FORMAT_SMIME,				/* As CMS with MSG-specific behaviour */
	CRYPT_FORMAT_PGP,				/* PGP format */
	CRYPT_FORMAT_SSH,				/* SSH format */
	CRYPT_FORMAT_SSL,				/* SSL format */
	CRYPT_FORMAT_LAST				/* Last possible format type */
	} CRYPT_FORMAT_TYPE;

/* Envelope information types */

typedef enum {
	/* No information */
	CRYPT_ENVINFO_NONE,				/* No envelope information */

	/* Pseudo-information on an envelope or meta-information which is used to
	   control the way data in an envelope is processed */
	CRYPT_ENVINFO_DATASIZE,			/* Data size information */
	CRYPT_ENVINFO_COMPRESSION,		/* Compression information */
	CRYPT_ENVINFO_CONTENTTYPE,		/* Inner CMS content type */
	CRYPT_ENVINFO_DETACHEDSIGNATURE,/* Generate CMS detached signature */
	CRYPT_ENVINFO_SIGNATURE_RESULT,	/* Signature check result */
	CRYPT_ENVINFO_CURRENT_COMPONENT,/* Env.information cursor management */

	/* Resources required for enveloping/deenveloping */
	CRYPT_ENVINFO_PASSWORD,			/* User password */
	CRYPT_ENVINFO_KEY,				/* Conventional encryption key */
	CRYPT_ENVINFO_SIGNATURE,		/* Signature/signature check key */
	CRYPT_ENVINFO_SIGNATURE_EXTRADATA,	/* Extra information added to CMS sigs */
	CRYPT_ENVINFO_PUBLICKEY,		/* PKC encryption key */
	CRYPT_ENVINFO_PRIVATEKEY,		/* PKC decryption key */
	CRYPT_ENVINFO_SESSIONKEY,		/* Session key */
	CRYPT_ENVINFO_HASH,				/* Hash algorithm */
	CRYPT_ENVINFO_MAC,				/* MAC key */

	/* Keysets used to retrieve keys needed for enveloping/deenveloping */
	CRYPT_ENVINFO_KEYSET_SIGCHECK,	/* Signature check keyset */
	CRYPT_ENVINFO_KEYSET_ENCRYPT,	/* PKC encryption keyset */
	CRYPT_ENVINFO_KEYSET_DECRYPT,	/* PKC decryption keyset */

	CRYPT_ENVINFO_LAST				/* Last possible envelope info type */
	} CRYPT_ENVINFO_TYPE;

/* Certificate information types */

typedef enum {
	/* No information */
	CRYPT_CERTINFO_NONE,			/* No certificate information */

	/* Pseudo-information on a cert object or meta-information which is used
	   to control the way a cert object is processed */
	CRYPT_CERTINFO_SELFSIGNED,		/* Cert is self-signed */
	CRYPT_CERTINFO_IMMUTABLE,		/* Cert is signed and immutable */
	CRYPT_CERTINFO_CERTTYPE,		/* Certificate object type */
	CRYPT_CERTINFO_FINGERPRINT,		/* Certificate fingerprints */
		CRYPT_CERTINFO_FINGERPRINT_MD5 = CRYPT_CERTINFO_FINGERPRINT,
	CRYPT_CERTINFO_FINGERPRINT_SHA,
	CRYPT_CERTINFO_CURRENT_CERTIFICATE,	/* Certificate cursor management */
	CRYPT_CERTINFO_CURRENT_EXTENSION,
	CRYPT_CERTINFO_CURRENT_FIELD,
	CRYPT_CERTINFO_CURRENT_COMPONENT,	/* Extension cursor management */
	CRYPT_CERTINFO_TRUSTED,			/* Cert is implicitly trusted */

	/* General certificate/CRL/cert request information */
	CRYPT_CERTINFO_SERIALNUMBER,	/* Serial number (read-only) */
	CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,	/* Public key */
	CRYPT_CERTINFO_USERCERTIFICATE,	/* User certificate */
		CRYPT_CERTINFO_CERTIFICATE = CRYPT_CERTINFO_USERCERTIFICATE,
	CRYPT_CERTINFO_ISSUERNAME,		/* Issuer DN (read-only) */
	CRYPT_CERTINFO_VALIDFROM,		/* Cert valid from time */
	CRYPT_CERTINFO_VALIDTO,			/* Cert valid to time */
	CRYPT_CERTINFO_SUBJECTNAME,		/* Subject DN */
	CRYPT_CERTINFO_ISSUERUNIQUEID,	/* Issuer unique ID (read-only) */
	CRYPT_CERTINFO_SUBJECTUNIQUEID,	/* Subject unique ID (read-only) */
	CRYPT_CERTINFO_CERTREQUEST,		/* Cert.request (DN + public key) */
	CRYPT_CERTINFO_THISUPDATE,		/* CRL current update time */
	CRYPT_CERTINFO_NEXTUPDATE,		/* CRL next update time */
	CRYPT_CERTINFO_REVOCATIONDATE,	/* CRL cert revocation time */

	/* X.520 Distinguished Name components.  This is a composite field, the
	   DN to be manipulated is selected through the addition of a
	   pseudocomponent, and then one of the following is used to access the
	   DN components directly */
	CRYPT_CERTINFO_COUNTRYNAME = 50,	/* countryName */
	CRYPT_CERTINFO_STATEORPROVINCENAME,	/* stateOrProvinceName */
	CRYPT_CERTINFO_LOCALITYNAME,		/* localityName */
	CRYPT_CERTINFO_ORGANIZATIONNAME,	/* organizationName */
		CRYPT_CERTINFO_ORGANISATIONNAME = CRYPT_CERTINFO_ORGANIZATIONNAME,
	CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,	/* organizationalUnitName */
		CRYPT_CERTINFO_ORGANISATIONALUNITNAME = CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
	CRYPT_CERTINFO_COMMONNAME,		/* commonName */

	/* X.509 General Name components.  These are handled in the same way as
	   the DN composite field, with the current GeneralName being selected by
	   a pseudo-component after which the individual components can be
	   modified through one of the following */
	CRYPT_CERTINFO_OTHERNAME_TYPEID,		/* otherName.typeID */
	CRYPT_CERTINFO_OTHERNAME_VALUE,			/* otherName.value */
	CRYPT_CERTINFO_RFC822NAME,				/* rfc822Name */
		CRYPT_CERTINFO_EMAIL = CRYPT_CERTINFO_RFC822NAME,
	CRYPT_CERTINFO_DNSNAME,					/* dNSName */
#if 0	/* Not supported yet, these are virtually never used and have an
		   insane internal structure */
	CRYPT_CERTINFO_X400ADDRESS,				/* x400Address */
#endif /* 0 */
	CRYPT_CERTINFO_DIRECTORYNAME,			/* directoryName */
	CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,	/* ediPartyName.nameAssigner */
	CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,	/* ediPartyName.partyName */
	CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,	/* uniformResourceIdentifier */
	CRYPT_CERTINFO_IPADDRESS,				/* iPAddress */
	CRYPT_CERTINFO_REGISTEREDID,			/* registeredID */

	/* X.509v3 certificate extensions.  Although it would be nicer to use
	   names which match the extensions more closely (eg
	   CRYPT_CERTINFO_BASICCONSTRAINTS_PATHLENCONSTRAINT), these exceed the
	   32-character ANSI minimum length for unique names, and get really
	   hairy once you get into the weird policy constraints extensions whose
	   names wrap around the screen about three times.

	   The following values are defined in OID order, this isn't absolutely
	   necessary but saves an extra layer of processing when encoding them */

	/* 1 3 6 1 5 5 7 1 1 authorityInfoAccess */
	CRYPT_CERTINFO_AUTHORITYINFOACCESS = 100,
	CRYPT_CERTINFO_AUTHORITYINFO_OCSP,	/* accessDescription.accessLocation */
	CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,	/* accessDescription.accessLocation */

	/* 1 3 101 1 4 1 strongExtranet */
	CRYPT_CERTINFO_STRONGEXTRANET,
	CRYPT_CERTINFO_STRONGEXTRANET_ZONE,	/* sxNetIDList.sxNetID.zone */
	CRYPT_CERTINFO_STRONGEXTRANET_ID,	/* sxNetIDList.sxNetID.id */

	/* 2 5 29 9 subjectDirectoryAttributes */
	CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES,
	CRYPT_CERTINFO_SUBJECTDIR_TYPE,			/* attribute.type */
	CRYPT_CERTINFO_SUBJECTDIR_VALUES,		/* attribute.values */

	/* 2 5 29 14 subjectKeyIdentifier */
	CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,

	/* 2 5 29 15 keyUsage */
	CRYPT_CERTINFO_KEYUSAGE,

	/* 2 5 29 16 privateKeyUsagePeriod */
	CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD,
	CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,	/* notBefore */
	CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,		/* notAfter */

	/* 2 5 29 17 subjectAltName */
	CRYPT_CERTINFO_SUBJECTALTNAME,

	/* 2 5 29 18 issuerAltName */
	CRYPT_CERTINFO_ISSUERALTNAME,

	/* 2 5 29 19 basicConstraints */
	CRYPT_CERTINFO_BASICCONSTRAINTS,
	CRYPT_CERTINFO_CA,						/* cA */
		CRYPT_CERTINFO_AUTHORITY = CRYPT_CERTINFO_CA,
	CRYPT_CERTINFO_PATHLENCONSTRAINT,		/* pathLenConstraint */

	/* 2 5 29 20 cRLNumber */
	CRYPT_CERTINFO_CRLNUMBER,

	/* 2 5 29 21 cRLReason */
	CRYPT_CERTINFO_CRLREASON,

	/* 2 5 29 23 holdInstructionCode */
	CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,

	/* 2 5 29 24 invalidityDate */
	CRYPT_CERTINFO_INVALIDITYDATE,

	/* 2 5 29 27 deltaCRLIndicator */
	CRYPT_CERTINFO_DELTACRLINDICATOR,

	/* 2 5 29 28 issuingDistributionPoint */
	CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT,
	CRYPT_CERTINFO_ISSUINGDIST_FULLNAME,	/* distributionPointName.fullName */
	CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY,	/* onlyContainsUserCerts */
	CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY,	/* onlyContainsCACerts */
	CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY,	/* onlySomeReasons */
	CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL,	/* indirectCRL */

	/* 2 5 29 29 certificateIssuer */
	CRYPT_CERTINFO_CERTIFICATEISSUER,

	/* 2 5 29 30 nameConstraints */
	CRYPT_CERTINFO_NAMECONSTRAINTS,
	CRYPT_CERTINFO_PERMITTEDSUBTREES,		/* permittedSubtrees */
	CRYPT_CERTINFO_EXCLUDEDSUBTREES,		/* excludedSubtrees */

	/* 2 5 29 31 cRLDistributionPoint */
	CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT,
	CRYPT_CERTINFO_CRLDIST_FULLNAME,		/* distributionPointName.fullName */
	CRYPT_CERTINFO_CRLDIST_REASONS,			/* reasons */
	CRYPT_CERTINFO_CRLDIST_CRLISSUER,		/* cRLIssuer */

	/* 2 5 29 32 certificatePolicies */
	CRYPT_CERTINFO_CERTIFICATEPOLICIES,
	CRYPT_CERTINFO_CERTPOLICYID,		/* policyInformation.policyIdentifier */
	CRYPT_CERTINFO_CERTPOLICY_CPSURI,
		/* policyInformation.policyQualifiers.qualifier.cPSuri */
	CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,
		/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization */
	CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS,
		/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers */
	CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT,
		/* policyInformation.policyQualifiers.qualifier.userNotice.explicitText */

	/* 2 5 29 33 policyMappings */
	CRYPT_CERTINFO_POLICYMAPPINGS,
	CRYPT_CERTINFO_ISSUERDOMAINPOLICY,	/* policyMappings.issuerDomainPolicy */
	CRYPT_CERTINFO_SUBJECTDOMAINPOLICY,	/* policyMappings.subjectDomainPolicy */

	/* 2 5 29 35 authorityKeyIdentifier */
	CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER,
	CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,	/* keyIdentifier */
	CRYPT_CERTINFO_AUTHORITY_CERTISSUER,	/* authorityCertIssuer */
	CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER,	/* authorityCertSerialNumber */

	/* 2 5 29 36 policyConstraints */
	CRYPT_CERTINFO_POLICYCONSTRAINTS,
	CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,	/* policyConstraints.requireExplicitPolicy */
	CRYPT_CERTINFO_INHIBITPOLICYMAPPING,	/* policyConstraints.inhibitPolicyMapping */

	/* 2 5 29 37 extKeyUsage */
	CRYPT_CERTINFO_EXTKEYUSAGE,
	CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,	/* individualCodeSigning */
	CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,	/* commercialCodeSigning */
	CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,	/* certTrustListSigning */
	CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,	/* timeStampSigning */
	CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,	/* serverGatedCrypto */
	CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,	/* encrypedFileSystem */
	CRYPT_CERTINFO_EXTKEY_SERVERAUTH,		/* serverAuth */
	CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,		/* clientAuth */
	CRYPT_CERTINFO_EXTKEY_CODESIGNING,		/* codeSigning */
	CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,	/* emailProtection */
	CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,	/* ipsecEndSystem */
	CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,		/* ipsecTunnel */
	CRYPT_CERTINFO_EXTKEY_IPSECUSER,		/* ipsecUser */
	CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,		/* timeStamping */
	CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,	/* serverGatedCrypto */
	CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,	/* serverGatedCrypto CA */

	/* 2 16 840 1 113730 1 x Netscape extensions */
	CRYPT_CERTINFO_NS_CERTTYPE,				/* netscape-cert-type */
	CRYPT_CERTINFO_NS_BASEURL,				/* netscape-base-url */
	CRYPT_CERTINFO_NS_REVOCATIONURL,		/* netscape-revocation-url */
	CRYPT_CERTINFO_NS_CAREVOCATIONURL,		/* netscape-ca-revocation-url */
	CRYPT_CERTINFO_NS_CERTRENEWALURL,		/* netscape-cert-renewal-url */
	CRYPT_CERTINFO_NS_CAPOLICYURL,			/* netscape-ca-policy-url */
	CRYPT_CERTINFO_NS_SSLSERVERNAME,		/* netscape-ssl-server-name */
	CRYPT_CERTINFO_NS_COMMENT,				/* netscape-comment */

	/* 2 23 42 7 0 SET hashedRootKey */
	CRYPT_CERTINFO_SET_HASHEDROOTKEY,
	CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT,	/* rootKeyThumbPrint */

	/* 2 23 42 7 1 SET certificateType */
	CRYPT_CERTINFO_SET_CERTIFICATETYPE,

	/* 2 23 42 7 2 SET merchantData */
	CRYPT_CERTINFO_SET_MERCHANTDATA,
	CRYPT_CERTINFO_SET_MERID,				/* merID */
	CRYPT_CERTINFO_SET_MERACQUIRERBIN,		/* merAcquirerBIN */
	CRYPT_CERTINFO_SET_MERCHANTLANGUAGE,	/* merNames.language */
	CRYPT_CERTINFO_SET_MERCHANTNAME,		/* merNames.name */
	CRYPT_CERTINFO_SET_MERCHANTCITY,		/* merNames.city */
	CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE,/* merNames.stateProvince */
	CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE,	/* merNames.postalCode */
	CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME,	/* merNames.countryName */
	CRYPT_CERTINFO_SET_MERCOUNTRY,			/* merCountry */
	CRYPT_CERTINFO_SET_MERAUTHFLAG,			/* merAuthFlag */

	/* 2 23 42 7 3 SET certCardRequired */
	CRYPT_CERTINFO_SET_CERTCARDREQUIRED,

	/* 2 23 42 7 4 SET tunneling */
	CRYPT_CERTINFO_SET_TUNNELING,
	CRYPT_CERTINFO_SET_TUNNELINGFLAG,		/* tunneling */
	CRYPT_CERTINFO_SET_TUNNELINGALGID,		/* tunnelingAlgID */

	/* S/MIME attributes */

	/* 1 2 840 113549 1 9 3 contentType */
	CRYPT_CERTINFO_CMS_CONTENTTYPE = 300,

	/* 1 2 840 113549 1 9 4 messageDigest */
	CRYPT_CERTINFO_CMS_MESSAGEDIGEST,

	/* 1 2 840 113549 1 9 5 signingTime */
	CRYPT_CERTINFO_CMS_SIGNINGTIME,

	/* 1 2 840 113549 1 9 6 counterSignature */
	CRYPT_CERTINFO_CMS_COUNTERSIGNATURE,	/* counterSignature */

	/* 1 2 840 113549 1 9 15 sMIMECapabilities */
	CRYPT_CERTINFO_CMS_SMIMECAPABILITIES,
	CRYPT_CERTINFO_CMS_SMIMECAP_3DES,		/* 3DES encryption */
	CRYPT_CERTINFO_CMS_SMIMECAP_CAST128,	/* CAST-128 encryption */
	CRYPT_CERTINFO_CMS_SMIMECAP_IDEA,		/* IDEA encryption */
	CRYPT_CERTINFO_CMS_SMIMECAP_RC2,		/* RC2 encryption (w.128 key) */
	CRYPT_CERTINFO_CMS_SMIMECAP_RC5,		/* RC5 encryption (w.128 key) */
	CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK,	/* Skipjack encryption */
	CRYPT_CERTINFO_CMS_SMIMECAP_DES,		/* DES encryption */
	CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA,	/* preferSignedData */
	CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY,	/* canNotDecryptAny */

	/* 1 2 840 113549 1 9 16 2 1 receiptRequest */
	CRYPT_CERTINFO_CMS_RECEIPTREQUEST,
	CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER, /* contentIdentifier */
	CRYPT_CERTINFO_CMS_RECEIPT_FROM,		/* receiptsFrom */
	CRYPT_CERTINFO_CMS_RECEIPT_TO,			/* receiptsTo */

	/* 1 2 840 113549 1 9 16 2 2 essSecurityLabel */
	CRYPT_CERTINFO_CMS_SECURITYLABEL,
	CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION, /* securityClassification */
	CRYPT_CERTINFO_CMS_SECLABEL_POLICY,		/* securityPolicyIdentifier */
	CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK,/* privacyMark */
	CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE,	/* securityCategories.securityCategory.type */
	CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE,	/* securityCategories.securityCategory.value */

	/* 1 2 840 113549 1 9 16 2 3 mlExpansionHistory */
	CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY,
	CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER, /* mlData.mailListIdentifier.issuerAndSerialNumber */
	CRYPT_CERTINFO_CMS_MLEXP_TIME,			/* mlData.expansionTime */
	CRYPT_CERTINFO_CMS_MLEXP_NONE,			/* mlData.mlReceiptPolicy.none */
	CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF,		/* mlData.mlReceiptPolicy.insteadOf.generalNames.generalName */
	CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO,	/* mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName */

	/* 1 2 840 113549 1 9 16 2 4 contentHints */
	CRYPT_CERTINFO_CMS_CONTENTHINTS,
	CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION,	/* contentDescription */
	CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE,	/* contentType */

	/* 1 2 840 113549 1 9 16 2 8 macValue */
	CRYPT_CERTINFO_CMS_MACVALUE,			/* macValue */

	/* 1 2 840 113549 1 9 16 2 9 equivalentLabels */
	CRYPT_CERTINFO_CMS_EQUIVALENTLABEL,
	CRYPT_CERTINFO_CMS_EQVLABEL_POLICY,		/* securityPolicyIdentifier */
	CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION, /* securityClassification */
	CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK,/* privacyMark */
	CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE,	/* securityCategories.securityCategory.type */
	CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE,	/* securityCategories.securityCategory.value */

	/* 1 2 840 113549 1 9 16 2 12 signingCertificate */
	CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
	CRYPT_CERTINFO_CMS_SIGNINGCERT_CERTS,	/* certs.essCertID.certHash */
	CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES,/* policies.policyInformation.policyIdentifier */

	/* 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo */
	CRYPT_CERTINFO_CMS_SPCAGENCYINFO,
	CRYPT_CERTINFO_CMS_SPCAGENCYURL,		/* spcAgencyInfo.url */

	/* 1 3 6 1 4 1 311 2 1 11 spcStatementType */
	CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE,
	CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING,	/* individualCodeSigning */
	CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING,	/* commercialCodeSigning */

	/* 1 3 6 1 4 1 311 2 1 12 spcOpusInfo */
	CRYPT_CERTINFO_CMS_SPCOPUSINFO,

	CRYPT_CERTINFO_LAST,			/* Last possible certificate info type */

	/* Useful defines used internally for range checking */
	CRYPT_FIRST_PSEUDOINFO = CRYPT_CERTINFO_SELFSIGNED,
	CRYPT_LAST_PSEUDOINFO = CRYPT_CERTINFO_TRUSTED,
	CRYPT_FIRST_DN = CRYPT_CERTINFO_COUNTRYNAME,
	CRYPT_LAST_DN = CRYPT_CERTINFO_COMMONNAME,
	CRYPT_FIRST_GENERALNAME = CRYPT_CERTINFO_OTHERNAME_TYPEID,
	CRYPT_LAST_GENERALNAME = CRYPT_CERTINFO_REGISTEREDID,
	CRYPT_FIRST_EXTENSION = CRYPT_CERTINFO_AUTHORITYINFOACCESS,
	CRYPT_LAST_EXTENSION = CRYPT_CERTINFO_SET_TUNNELINGALGID,
	CRYPT_FIRST_CMS = CRYPT_CERTINFO_CMS_CONTENTTYPE,
	CRYPT_LAST_CMS = CRYPT_CERTINFO_LAST - 1
	} CRYPT_CERTINFO_TYPE;

/* Flags for the X.509v3 keyUsage extension */

#define CRYPT_KEYUSAGE_NONE					0x000
#define CRYPT_KEYUSAGE_DIGITALSIGNATURE		0x001
#define CRYPT_KEYUSAGE_NONREPUDIATION		0x002
#define CRYPT_KEYUSAGE_KEYENCIPHERMENT		0x004
#define CRYPT_KEYUSAGE_DATAENCIPHERMENT		0x008
#define CRYPT_KEYUSAGE_KEYAGREEMENT			0x010
#define CRYPT_KEYUSAGE_KEYCERTSIGN			0x020
#define CRYPT_KEYUSAGE_CRLSIGN				0x040
#define CRYPT_KEYUSAGE_ENCIPHERONLY			0x080
#define CRYPT_KEYUSAGE_DECIPHERONLY			0x100
#define CRYPT_KEYUSAGE_LAST					0x200	/* Last possible value */

/* X.509v3 cRLReason codes */

enum { CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLREASON_KEYCOMPROMISE,
	   CRYPT_CRLREASON_CACOMPROMISE, CRYPT_CRLREASON_AFFILIATIONCHANGED,
	   CRYPT_CRLREASON_SUPERSEDED, CRYPT_CRLREASON_CESSATIONOFOPERATION,
	   CRYPT_CRLREASON_CERTIFICATEHOLD, CRYPT_CRLREASON_REMOVEFROMCRL = 8,
	   CRYPT_CRLREASON_LAST };

/* X.509v3 CRL reason flags.  These identify the same thing as the cRLReason
   codes but allow for multiple reasons to be specified.  Note that these
   don't follow the X.509 naming since in that scheme the enumerated types
   and bitflags have the same name */

#define CRYPT_CRLREASONFLAG_UNUSED				0x001
#define CRYPT_CRLREASONFLAG_KEYCOMPROMISE		0x002
#define CRYPT_CRLREASONFLAG_CACOMPROMISE		0x004
#define CRYPT_CRLREASONFLAG_AFFILIATIONCHANGED	0x008
#define CRYPT_CRLREASONFLAG_SUPERSEDED			0x010
#define CRYPT_CRLREASONFLAG_CESSATIONOFOPERATION 0x020
#define CRYPT_CRLREASONFLAG_CERTIFICATEHOLD		0x040
#define CRYPT_CRLREASONFLAG_LAST				0x080	/* Last poss.value */

/* X.509v3 CRL holdInstruction codes */

enum { CRYPT_HOLDINSTRUCTION_NONE, CRYPT_HOLDINSTRUCTION_CALLISSUER,
	   CRYPT_HOLDINSTRUCTION_REJECT, CRYPT_HOLDINSTRUCTION_PICKUPTOKEN,
	   CRYPT_HOLDINSTRUCTION_LAST };

/* Flags for the Netscape netscape-cert-type extension */

#define CRYPT_NS_CERTTYPE_SSLCLIENT			0x001
#define CRYPT_NS_CERTTYPE_SSLSERVER			0x002
#define CRYPT_NS_CERTTYPE_SMIME				0x004
#define CRYPT_NS_CERTTYPE_OBJECTSIGNING		0x008
#define CRYPT_NS_CERTTYPE_RESERVED			0x010
#define CRYPT_NS_CERTTYPE_SSLCA				0x020
#define CRYPT_NS_CERTTYPE_SMIMECA			0x040
#define CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA	0x080
#define CRYPT_NS_CERTTYPE_LAST				0x100	/* Last possible value */

/* CMS contentType values */

typedef enum { CRYPT_CONTENT_DATA, CRYPT_CONTENT_SIGNEDDATA,
			   CRYPT_CONTENT_ENVELOPEDDATA,
			   CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
			   CRYPT_CONTENT_DIGESTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA,
			   CRYPT_CONTENT_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_LAST
			   } CRYPT_CONTENT_TYPE;

/* ESS securityClassification codes */

enum { CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_UNCLASSIFIED,
	   CRYPT_CLASSIFICATION_RESTRICTED, CRYPT_CLASSIFICATION_CONFIDENTIAL,
	   CRYPT_CLASSIFICATION_SECRET, CRYPT_CLASSIFICATION_TOP_SECRET,
	   CRYPT_CLASSIFICATION_LAST = 255 };

/* Certificate error types */

typedef enum {
	CRYPT_CERTERROR_NONE,			/* No certificate error */
	CRYPT_CERTERROR_SIZE,			/* Item too small or large */
	CRYPT_CERTERROR_VALUE,			/* Item value is invalid */
	CRYPT_CERTERROR_CONSTRAINT,		/* Constraint violation in item */
	CRYPT_CERTERROR_ISSUERCONSTRAINT,	/* Constraint viol.in issuing cert */
	CRYPT_CERTERROR_ABSENT,			/* Required item missing */
	CRYPT_CERTERROR_PRESENT,		/* Non-allowed item present */
	CRYPT_CERTERROR_LAST			/* Last possible cert.error */
	} CRYPT_CERTERROR_TYPE;

/* Session information types */

typedef enum {
	/* No information */
	CRYPT_SESSINFO_NONE,			/* No session information */

	/* Pseudo-information on a session or meta-information which is used to
	   control the way a session is managed */

	/* Resources required to establish the session */
	CRYPT_SESSINFO_KEY_ENCRYPTION,	/* Encryption key */
	CRYPT_SESSINFO_KEY_AUTHENTICATION,	/* Authentication key */

	CRYPT_SESSINFO_LAST				/* Last possible session info type */
	} CRYPT_SESSINFO_TYPE;

/* Session datagram types */

typedef enum {
	CRYPT_SESSIONDATA_NONE,			/* No data */
	CRYPT_SESSIONDATA_HELLO,		/* Client/server hello */
	CRYPT_SESSIONDATA_KEYEXCHANGE,	/* Client/server key exchange */
	CRYPT_SESSIONDATA_AUTHENTICATION,	/* Client/server authentication */
	CRYPT_SESSIONDATA_LAST			/* Last possible session info type */
	} CRYPT_SESSIONDATA_TYPE;

/* Object property types */

typedef enum {
	CRYPT_PROPERTY_NONE,			/* No property */
	CRYPT_PROPERTY_HIGHSECURITY,	/* Owned+non-forwardable+locked */
	CRYPT_PROPERTY_OWNER,			/* Object owner */
	CRYPT_PROPERTY_FORWARDABLE,		/* No.of times object can be forwarded */
	CRYPT_PROPERTY_LOCKED,			/* Whether properties can be chged/read */
	CRYPT_PROPERTY_LAST				/* Last possible property type */
	} CRYPT_PROPERTY_TYPE;

/* Device control options */

typedef enum {
	CRYPT_DEVICECONTROL_NONE,		/* No device control */
	CRYPT_DEVICECONTROL_INITIALISE,	/* Initialise device for use */
		CRYPT_DEVICECONTROL_INITIALIZE = CRYPT_DEVICECONTROL_INITIALISE,
	CRYPT_DEVICECONTROL_AUTH_USER,	/* Authenticate user to device */
	CRYPT_DEVICECONTROL_AUTH_SUPERVISOR,	/* Authenticate supervisor to dev.*/
	CRYPT_DEVICECONTROL_SET_AUTH_USER,	/* Set user authent.value */
	CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR,	/* Set supervisor auth.val.*/
	CRYPT_DEVICECONTROL_ZEROISE,	/* Zeroise device */
		CRYPT_DEVICECONTROL_ZEROIZE = CRYPT_DEVICECONTROL_ZEROISE,
	CRYPT_DEVICECONTROL_LAST		/* Last possible device control */
	} CRYPT_DEVICECONTROL_TYPE;

/* Configuration options */

typedef enum {
	CRYPT_OPTION_NONE,				/* Non-option */

	/* cryptlib information (read-only) */
	CRYPT_OPTION_INFO_DESCRIPTION,	/* Text description */
	CRYPT_OPTION_INFO_COPYRIGHT,	/* Copyright notice */
	CRYPT_OPTION_INFO_MAJORVERSION,	/* Major release version */
	CRYPT_OPTION_INFO_MINORVERSION,	/* Minor release version */

	/* Encryption options */
	CRYPT_OPTION_ENCR_ALGO,			/* Encryption algorithm */
	CRYPT_OPTION_ENCR_MODE,			/* Encryption mode */
	CRYPT_OPTION_ENCR_HASH,			/* Hash algorithm */

	/* PKC options */
	CRYPT_OPTION_PKC_ALGO,			/* Public-key encryption algorithm */
	CRYPT_OPTION_PKC_KEYSIZE,		/* Public-key encryption key size */

	/* Signature options */
	CRYPT_OPTION_SIG_ALGO,			/* Signature algorithm */
	CRYPT_OPTION_SIG_KEYSIZE,		/* Signature keysize */

	/* Keying options */
	CRYPT_OPTION_KEYING_ALGO,		/* Key processing algorithm */
	CRYPT_OPTION_KEYING_ITERATIONS,	/* Key processing iterations */

	/* Certificate options */
	CRYPT_OPTION_CERT_CREATEV3CERT,	/* Whether to create X.509v3 certs */
	CRYPT_OPTION_CERT_PKCS10ALT,	/* Use alternative PKCS #10 encoding */
	CRYPT_OPTION_CERT_CHECKENCODING,/* Check for valid ASN.1 encoding */
	CRYPT_OPTION_CERT_FIXSTRINGS,	/* Whether to fix encoding of strings */
	CRYPT_OPTION_CERT_FIXEMAILADDRESS,	/* Whether to fix encoding of email addr.*/
	CRYPT_OPTION_CERT_ISSUERNAMEBLOB,	/* Whether to treat iName as a blob */
	CRYPT_OPTION_CERT_KEYIDBLOB,	/* Whether to treat keyID as a blob */
	CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES,	/* Whether to sign unrecog.attrs */
	CRYPT_OPTION_CERT_TRUSTCHAINROOT,	/* Whether to trust cert chain root */
	CRYPT_OPTION_CERT_VALIDITY,		/* Certificate validity period */
	CRYPT_OPTION_CERT_UPDATEINTERVAL,	/* CRL update interval */
	CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING,
	CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING, /* Enforce validity nesting on R/W */
	CRYPT_OPTION_CERT_ENCODE_CRITICAL,
	CRYPT_OPTION_CERT_DECODE_CRITICAL, /* Enforce critical flag in extensions */

	/* Keyset options */
	CRYPT_OPTION_KEYS_PUBLIC,		/* Default encryption PKC database */
	CRYPT_OPTION_KEYS_PRIVATE,		/* Default decryption PKC database */
	CRYPT_OPTION_KEYS_SIGCHECK,		/* Default sig.check PKC database */
	CRYPT_OPTION_KEYS_SIGNATURE,	/* Default sig.generation PKC database */

	/* File keyset options */
	CRYPT_OPTION_KEYS_FILE_PRIVATE,	/* Private key file */
	CRYPT_OPTION_KEYS_FILE_SIGNATURE,/* Signature key file */

	/* PGP keyset options */
	CRYPT_OPTION_KEYS_PGP_PUBLIC,	/* PGP public keyring */
	CRYPT_OPTION_KEYS_PGP_PRIVATE,	/* PGP private keyring */
	CRYPT_OPTION_KEYS_PGP_SIGCHECK,	/* PGP signature check keyring */
	CRYPT_OPTION_KEYS_PGP_SIGNATURE,/* PGP signature gen.keyring */

	/* RDBMS keyset options */
	CRYPT_OPTION_KEYS_DBMS_NAMETABLE,	/* Name of key database table */
	CRYPT_OPTION_KEYS_DBMS_NAMECRLTABLE,/* Name of CRL table */
	CRYPT_OPTION_KEYS_DBMS_NAME_C,		/* Name of key owner C column */
	CRYPT_OPTION_KEYS_DBMS_NAME_SP,		/* Name of key owner SP column */
	CRYPT_OPTION_KEYS_DBMS_NAME_L,		/* Name of key owner L column */
	CRYPT_OPTION_KEYS_DBMS_NAME_O,		/* Name of key owner O column */
	CRYPT_OPTION_KEYS_DBMS_NAME_OU,		/* Name of key owner OU column */
	CRYPT_OPTION_KEYS_DBMS_NAME_CN,		/* Name of key owner CN column */
	CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL,	/* Name of key owner email column */
	CRYPT_OPTION_KEYS_DBMS_NAMEDATE,	/* Name of key expiry date column */
	CRYPT_OPTION_KEYS_DBMS_NAMENAMEID,	/* Name of key nameID column */
	CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID,/* Name of key issuerID column */
	CRYPT_OPTION_KEYS_DBMS_NAMEKEYID,	/* Name of key keyID column */
	CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA,	/* Name of key data column */

	/* HTTP keyset access options */
	CRYPT_OPTION_KEYS_HTTP_PROXY,		/* URL of web proxy */
	CRYPT_OPTION_KEYS_HTTP_TIMEOUT,		/* Timeout for read */

	/* LDAP keyset options */
	CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS,	/* Object class */
	CRYPT_OPTION_KEYS_LDAP_CACERTNAME,	/* CA certificate attribute name */
	CRYPT_OPTION_KEYS_LDAP_CERTNAME,	/* Certificate attribute name */
	CRYPT_OPTION_KEYS_LDAP_CRLNAME,		/* CRL attribute name */
	CRYPT_OPTION_KEYS_LDAP_EMAILNAME,	/* Email attribute name */

	/* Crypto device options */
	CRYPT_OPTION_DEVICE_PKCS11_DVR01,	/* Name of first PKCS #11 driver */
	CRYPT_OPTION_DEVICE_PKCS11_DVR02,	/* Name of second PKCS #11 driver */
	CRYPT_OPTION_DEVICE_PKCS11_DVR03,	/* Name of third PKCS #11 driver */
	CRYPT_OPTION_DEVICE_PKCS11_DVR04,	/* Name of fourth PKCS #11 driver */
	CRYPT_OPTION_DEVICE_PKCS11_DVR05,	/* Name of fifth PKCS #11 driver */
	CRYPT_OPTION_DEVICE_SERIALRNG,		/* Serial-port-based RNG name */
	CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS,/* Serial RNG parameters */
	CRYPT_OPTION_DEVICE_SERIALRNG_ONLY,	/* Whether to use only serial RNG */

	/* CMS/SMIME options */
	CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,	/* Add default CMS attributes */
		CRYPT_OPTION_SMIME_DEFAULTATTRIBUTES = CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,

	/* Miscellaneous options */
	CRYPT_OPTION_MISC_FORCELOCK,	/* Whether to force memory locking */
	CRYPT_OPTION_MISC_ASYNCINIT,	/* Whether to init cryptlib async'ly */
	CRYPT_OPTION_LAST				/* Last config option */
	} CRYPT_OPTION_TYPE;

/****************************************************************************
*																			*
*						Library-Wide Constants and Definitions				*
*																			*
****************************************************************************/

/* The maximum user key size - 2048 bits */

#define CRYPT_MAX_KEYSIZE		256

/* The maximum IV size - 256 bits (required for the LEAF+IV Fortezza IV) */

#define CRYPT_MAX_IVSIZE		32

/* The maximum public-key component size - 4096 bits */

#define CRYPT_MAX_PKCSIZE		512

/* The maximum hash size - 256 bits */

#define CRYPT_MAX_HASHSIZE		32

/* The maximum size of a text string (eg key owner name) */

#define CRYPT_MAX_TEXTSIZE		64

/* A magic value indicating that the default setting for this parameter
   should be used */

#define CRYPT_USE_DEFAULT		-1

/* A magic value for unused parameters */

#define CRYPT_UNUSED			-2

/* The endianness of the external components of the PKC key */

#define CRYPT_COMPONENTS_BIGENDIAN		0
#define CRYPT_COMPONENTS_LITTLENDIAN	1

/* Whether the PKC key is a public or private key */

#define CRYPT_KEYTYPE_PRIVATE	0
#define CRYPT_KEYTYPE_PUBLIC	1

/* The type of information polling to perform to get random seed information */

#define CRYPT_RANDOM_FASTPOLL	-1
#define CRYPT_RANDOM_SLOWPOLL	-2

/* Special key ID's for getFirst()/getNext() functionality in flat file
   keysets */

#define CRYPT_KEYSET_GETFIRST	( ( void CPTR ) -10 )
#define CRYPT_KEYSET_GETNEXT	( ( void CPTR ) -11 )

/* Special keyset contexts for begin/end bulk update functionality in
   keysets */

#define CRYPT_KEYUPDATE_BEGIN	-20
#define CRYPT_KEYUPDATE_END		-21

/* Cursor positioning codes for certificate/CRL extensions */

#define CRYPT_CURSOR_FIRST		-30
#define CRYPT_CURSOR_PREVIOUS	-31
#define CRYPT_CURSOR_NEXT		-32
#define CRYPT_CURSOR_LAST		-33

/* Options passed to cryptOpenKeyset() and cryptOpenKeysetEx() */

typedef enum {
	CRYPT_KEYOPT_NONE,				/* No options */
	CRYPT_KEYOPT_READONLY,			/* Open keyset in read-only mode */
	CRYPT_KEYOPT_CREATE,			/* Create a new keyset */
	CRYPT_KEYOPT_LAST				/* Last possible key option type */
	} CRYPT_KEYOPT_TYPE;

/* Macros to convert to and from the bit counts used for some encryption
   parameters */

#define bitsToBytes(bits)	( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits(bytes)	( ( bytes ) << 3 )

/* The various cryptlib objects - these are just integer handles */

typedef int CRYPT_CERTIFICATE;
typedef int CRYPT_CONTEXT;
typedef int CRYPT_DEVICE;
typedef int CRYPT_ENVELOPE;
typedef int CRYPT_KEYSET;
typedef int CRYPT_SESSION;

/* Sometimes we don't know the exact type of a cryptlib object, so we use a
   generic handle type to identify it */

typedef int CRYPT_HANDLE;

/****************************************************************************
*																			*
*							Encryption Data Structures						*
*																			*
****************************************************************************/

/* Results returned from the encryption capability query */

typedef struct {
	/* The algorithm, encryption mode, and algorithm and mode names */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */
	char algoName[ CRYPT_MAX_TEXTSIZE ];	/* The algorithm name */
	char modeName[ CRYPT_MAX_TEXTSIZE ];	/* The mode name */

	/* The algorithm parameters */
	int blockSize;					/* The basic block size of the algorithm */
	int minKeySize;					/* Minimum key size in bytes */
	int keySize;					/* Recommended key size in bytes */
	int maxKeySize;					/* Maximum key size in bytes */
	int minIVsize;					/* Minimum IV size in bytes */
	int ivSize;						/* Recommended IV size in bytes */
	int maxIVsize;					/* Maximum IV size in bytes */
	int actualKeySize;				/* Actual key size in bytes */

	/* Miscellaneous information (only used by some algorithms) */
	unsigned char hashValue[ CRYPT_MAX_HASHSIZE ];
									/* Hash algorithm hash value */
	} CRYPT_QUERY_INFO;

/* Results returned from the encryption object query.  These provide
   information on the objects created by cryptExportKey()/
   cryptCreateSignature() */

typedef struct {
	/* The object type and size */
	CRYPT_OBJECT_TYPE objectType;	/* The object type */
	int objectSize;					/* The object size */

	/* The encryption algorithm and mode */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */

	/* The key derivation algorithm and iteration count for EncryptedKey
	   objects */
	CRYPT_ALGO keySetupAlgo;		/* Key setup algorithm */
	int keySetupIterations;			/* Key setup iteration count */

	/* The hash algorithm for Signature objects */
	CRYPT_ALGO hashAlgo;			/* Hash algorithm */

	/* The algorithm-specific information for EncryptedKey objects.  The
	   algorithm-specific information can be passed directly to
	   cryptCreateContextEx() for any algorithm (even those which would
	   normally use cryptCreateContext()) */
	void *cryptContextExInfo;		/* Algo-specific information */
	char _contextInfo[ 32 ];		/* Storage for alg-specific info */
	} CRYPT_OBJECT_INFO;

/* Extra algorithm-specific information for the conventional encryption
   algorithms, stored within a crypt context.  Set the parameter values to
   CRYPT_USE_DEFAULT to use the default values for this algorithm */

typedef struct {
	int rounds;					/* Number of encryption rounds */
	} CRYPT_INFO_RC5;

typedef struct {
	int useSaferSK;				/* Whether to use strengthened-key version */
	int rounds;					/* Number of encryption rounds */
	} CRYPT_INFO_SAFER;

/* Key information for the public-key encryption algorithms.  These fields
   are not accessed directly, but can be manipulated with the init/set/
   destroyComponents() macros */

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

	/* Public components */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime */
	int pLen;					/* Length of prime in bits */
	unsigned char g[ CRYPT_MAX_PKCSIZE ];	/* Base */
	int gLen;					/* Length of base in bits */
	} CRYPT_PKCINFO_DH;

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

	/* Public components */
	unsigned char n[ CRYPT_MAX_PKCSIZE ];	/* Modulus */
	int nLen;					/* Length of modulus in bits */
	unsigned char e[ CRYPT_MAX_PKCSIZE ];	/* Public exponent */
	int eLen;					/* Length of public exponent in bits */

	/* Private components */
	unsigned char d[ CRYPT_MAX_PKCSIZE ];	/* Private exponent */
	int dLen;					/* Length of private exponent in bits */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime factor 1 */
	int pLen;					/* Length of prime factor 1 in bits */
	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime factor 2 */
	int qLen;					/* Length of prime factor 2 in bits */
	unsigned char u[ CRYPT_MAX_PKCSIZE ];	/* Mult.inverse of q, mod p */
	int uLen;					/* Length of private exponent in bits */
	unsigned char e1[ CRYPT_MAX_PKCSIZE ];	/* Private exponent 1 (PKCS) */
	int e1Len;					/* Length of private exponent in bits */
	unsigned char e2[ CRYPT_MAX_PKCSIZE ];	/* Private exponent 2 (PKCS) */
	int e2Len;					/* Length of private exponent in bits */
	} CRYPT_PKCINFO_RSA;

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

	/* Public components */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime modulus */
	int pLen;					/* Length of prime modulus in bits */
	unsigned char q[ CRYPT_MAX_PKCSIZE ];	/* Prime divisor */
	int qLen;					/* Length of prime divisor in bits */
	unsigned char g[ CRYPT_MAX_PKCSIZE ];	/* h^( ( p - 1 ) / q ) mod p */
	int gLen;					/* Length of g in bits */
	unsigned char y[ CRYPT_MAX_PKCSIZE ];	/* Public random integer */
	int yLen;					/* Length of public integer in bits */

	/* Private components */
	unsigned char x[ CRYPT_MAX_PKCSIZE ];	/* Private random integer */
	int xLen;					/* Length of private integer in bits */
	} CRYPT_PKCINFO_DSA;

typedef struct {
	/* Status information */
	int endianness;				/* Endianness of integer strings */
	int isPublicKey;			/* Whether this is a public or private key */

	/* Public components */
	unsigned char p[ CRYPT_MAX_PKCSIZE ];	/* Prime modulus */
	int pLen;					/* Length of prime modulus in bits */
	unsigned char g[ CRYPT_MAX_PKCSIZE ];	/* Generator */
	int gLen;					/* Length of g in bits */
	unsigned char y[ CRYPT_MAX_PKCSIZE ];	/* Public random integer */
	int yLen;					/* Length of public integer in bits */

	/* Private components */
	unsigned char x[ CRYPT_MAX_PKCSIZE ];	/* Private random integer */
	int xLen;					/* Length of private integer in bits */
	} CRYPT_PKCINFO_ELGAMAL;

/* Macros to initialise and destroy the structure which stores the components
   of a public key */

#define cryptInitComponents( componentInfo, componentEndianness, componentKeyType ) \
	{ memset( componentInfo, 0, sizeof( *componentInfo ) ); \
	  componentInfo##->endianness = componentEndianness; \
	  componentInfo##->isPublicKey = componentKeyType; }

#define cryptDestroyComponents( componentInfo ) \
	memset( componentInfo, 0, sizeof( *componentInfo ) )

/* Macros to set a component of a public key */

#define cryptSetComponent( destination, source, length ) \
	{ memcpy( destination, source, bitsToBytes( length ) ); \
	  destination##Len = length; }

/****************************************************************************
*																			*
*								Status Codes								*
*																			*
****************************************************************************/

/* No error in function call */

#define CRYPT_OK			0		/* No error */

/* Internal errors */

#define CRYPT_ERROR			-1		/* Nonspecific error */
#define CRYPT_SELFTEST		-2		/* Failed self-test */

/* Error in parameters passed to function */

#define CRYPT_BADPARM		-10		/* Generic bad argument to function */
#define CRYPT_BADPARM1		-11		/* Bad argument, parameter 1 */
#define CRYPT_BADPARM2		-12		/* Bad argument, parameter 2 */
#define CRYPT_BADPARM3		-13		/* Bad argument, parameter 3 */
#define CRYPT_BADPARM4		-14		/* Bad argument, parameter 4 */
#define CRYPT_BADPARM5		-15		/* Bad argument, parameter 5 */
#define CRYPT_BADPARM6		-16		/* Bad argument, parameter 6 */
#define CRYPT_BADPARM7		-17		/* Bad argument, parameter 7 */
#define CRYPT_BADPARM8		-18		/* Bad argument, parameter 8 */
#define CRYPT_BADPARM9		-19		/* Bad argument, parameter 9 */
#define CRYPT_BADPARM10		-20		/* Bad argument, parameter 10 */

/* Errors due to insufficient resources */

#define CRYPT_NOMEM			-50		/* Out of memory */
#define CRYPT_NOTINITED		-51		/* Data has not been initialised */
#define CRYPT_INITED		-52		/* Data has already been initialised */
#define CRYPT_NOSECURE		-53		/* Operation not available at requested sec.level */
#define CRYPT_NOALGO		-54		/* Algorithm unavailable */
#define CRYPT_NOMODE		-55		/* Encryption mode unavailable */
#define CRYPT_NOKEY			-56		/* Key not initialised */
#define CRYPT_NOIV			-57		/* IV not initialised */
#define CRYPT_NORANDOM		-58		/* No reliable random data available */

/* Security violations */

#define CRYPT_NOTAVAIL		-100	/* Operation not available for this argument */
#define CRYPT_NOPERM		-101	/* No permiss.to perform this operation */
#define CRYPT_WRONGKEY		-102	/* Incorrect key used to decrypt data */
#define CRYPT_INCOMPLETE	-103	/* Operation incomplete/still in progress */
#define CRYPT_COMPLETE		-104	/* Operation complete/can't continue */
#define CRYPT_ORPHAN		-105	/* Contexts remained allocated */
#define CRYPT_BUSY			-106	/* Resource in use by async operation */
#define CRYPT_SIGNALLED		-107	/* Resource destroyed by external event */

/* High-level function errors */

#define CRYPT_OVERFLOW		-150	/* Too much data supplied to function */
#define CRYPT_UNDERFLOW		-151	/* Not enough data supplied to function */
#define CRYPT_PKCCRYPT		-152	/* PKC en/decryption failed */
#define CRYPT_BADDATA		-153	/* Bad data format in object */
#define CRYPT_BADSIG		-154	/* Bad signature on data */
#define CRYPT_INVALID		-155	/* Invalid/inconsistent information */

/* Data access function errors */

#define CRYPT_DATA_OPEN		-200	/* Cannot open data object */
#define CRYPT_DATA_READ		-201	/* Cannot read item from data object */
#define CRYPT_DATA_WRITE	-202	/* Cannot write item to data object */
#define CRYPT_DATA_NOTFOUND	-203	/* Requested item not found in data obj.*/
#define CRYPT_DATA_DUPLICATE -204	/* Item already present in data object */

/* Data enveloping errors */

#define CRYPT_ENVELOPE_RESOURCE	-250	/* Need resource to proceed */

/* Macros to examine return values */

#define cryptStatusError( status )	( ( status ) < CRYPT_OK )
#define cryptStatusOK( status )		( ( status ) == CRYPT_OK )

/****************************************************************************
*																			*
*							Low-level Encryption Functions					*
*																			*
****************************************************************************/

/* The following is necessary to stop C++ name mangling */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Initialise and shut down cryptlib */

CRET cryptInit( void );
CRET cryptInitEx( void );
CRET cryptEnd( void );

/* Query cryptlibs capabilities */

CRET cryptQueryCapability( const CRYPT_ALGO cryptAlgo,
						   const CRYPT_MODE cryptMode,
						   CRYPT_QUERY_INFO CPTR cryptQueryInfo );
CRET cryptQueryContext( const CRYPT_HANDLE cryptHandle,
						CRYPT_QUERY_INFO CPTR cryptQueryInfo );

/* Createand destroy an encryption context */

CRET cryptCreateContext( CRYPT_CONTEXT CPTR cryptContext,
						 const CRYPT_ALGO cryptAlgo,
						 const CRYPT_MODE cryptMode );
CRET cryptCreateContextEx( CRYPT_CONTEXT CPTR cryptContext,
						   const CRYPT_ALGO cryptAlgo,
						   const CRYPT_MODE cryptMode,
						   const void CPTR cryptContextEx );
CRET cryptDestroyContext( const CRYPT_CONTEXT cryptContext );

/* Generic "destroy an object" function */

CRET cryptDestroyObject( const CRYPT_HANDLE cryptObject );

/* Get/set object properties */

CRET cryptGetObjectProperty( const CRYPT_HANDLE cryptObject,
							 const CRYPT_PROPERTY_TYPE property,
							 int CPTR value );
CRET cryptSetObjectProperty( const CRYPT_HANDLE cryptObject,
							 const CRYPT_PROPERTY_TYPE property,
							 const int value );

/* Load a user key into an encryption context, add random data to the random
   pool, get medium-strength random data from the random pool, generate a
   key into a context, or derive an encryption key from a variable-length
   user key */

CRET cryptLoadKey( const CRYPT_CONTEXT cryptContext, const void CPTR key,
				   const int keyLength );
CRET cryptAddRandom( const void CPTR randomData, const int randomDataLength );
CRET cryptGetRandom( void CPTR randomData, const int randomDataLength );
CRET cryptGenerateKey( const CRYPT_CONTEXT cryptContext );
CRET cryptGenerateKeyEx( const CRYPT_CONTEXT cryptContext,
						 const int keyLength );
CRET cryptDeriveKey( const CRYPT_CONTEXT cryptContext,
					 const void CPTR userKey, const int userKeyLength );
CRET cryptDeriveKeyEx( const CRYPT_CONTEXT cryptContext,
					   const void CPTR userKey, const int userKeyLength,
					   const CRYPT_ALGO algorithm, const int iterations );

/* Asynchronous operations */

CRET cryptGenerateKeyAsync( const CRYPT_CONTEXT cryptContext );
CRET cryptGenerateKeyAsyncEx( const CRYPT_CONTEXT cryptContext,
							  const int keyLength );
CRET cryptAsyncQuery( const CRYPT_CONTEXT cryptContext );
CRET cryptAsyncCancel( const CRYPT_CONTEXT cryptContext );

/* Load/retrieve an IV into/from an encryption context */

CRET cryptLoadIV( const CRYPT_CONTEXT cryptContext, const void CPTR iv,
				  const int ivLength );
CRET cryptRetrieveIV( const CRYPT_CONTEXT cryptContext, void CPTR iv );

/* Encrypt/decrypt/hash a block of memory */

CRET cryptEncrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length );
CRET cryptDecrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length );

/* Get extended information on the last error */

CRET cryptGetErrorInfo( const CRYPT_HANDLE cryptHandle, int CPTR errorCode,
						char CPTR errorString, int CPTR errorStringLength );
CRET cryptGetErrorMessage( const int error, char CPTR message,
						   int CPTR messageLength );

/****************************************************************************
*																			*
*							Mid-level Encryption Functions					*
*																			*
****************************************************************************/

/* Export and import an encrypted session key */

CRET cryptExportKey( void CPTR encryptedKey, int CPTR encryptedKeyLength,
					 const CRYPT_HANDLE exportKey,
					 const CRYPT_CONTEXT sessionKeyContext );
CRET cryptImportKey( void CPTR encryptedKey, const CRYPT_CONTEXT importKey,
					 CRYPT_CONTEXT CPTR sessionKeyContext );
CRET cryptExportKeyEx( void CPTR encryptedKey, int CPTR encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_HANDLE exportKey,
					   const CRYPT_CONTEXT sessionKeyContext );
CRET cryptImportKeyEx( void CPTR encryptedKey, const CRYPT_CONTEXT importKey,
					   CRYPT_CONTEXT CPTR sessionKeyContext );

/* Create and check a digital signature */

CRET cryptCreateSignature( void CPTR signature, int CPTR signatureLength,
						   const CRYPT_CONTEXT signContext,
						   const CRYPT_CONTEXT hashContext );
CRET cryptCreateSignatureEx( void CPTR signature, int CPTR signatureLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT signContext,
							 const CRYPT_CONTEXT hashContext,
							 const CRYPT_CERTIFICATE extraData );
CRET cryptCheckSignature( const void CPTR signature,
						  const CRYPT_HANDLE sigCheckKey,
						  const CRYPT_CONTEXT hashContext );
CRET cryptCheckSignatureEx( void CPTR signature,
							const CRYPT_HANDLE sigCheckKey,
							const CRYPT_CONTEXT hashContext,
							CRYPT_HANDLE *extraData );

/* Query a cryptlib data object */

CRET cryptQueryObject( const void CPTR object,
					   CRYPT_OBJECT_INFO CPTR cryptObjectInfo );

/****************************************************************************
*																			*
*								Key Managment Functions						*
*																			*
****************************************************************************/

/* Open and close a keyset */

CRET cryptKeysetOpen( CRYPT_KEYSET CPTR keyset, const CRYPT_KEYSET_TYPE keysetType,
					  const char CPTR name, const CRYPT_KEYOPT_TYPE options );
CRET cryptKeysetOpenEx( CRYPT_KEYSET CPTR keyset, const CRYPT_KEYSET_TYPE keysetType,
						const char CPTR name, const char CPTR param1,
						const char CPTR param2, const char CPTR param3,
						const CRYPT_KEYOPT_TYPE options );
CRET cryptKeysetClose( const CRYPT_KEYSET keyset );

/* Get a key from a keyset */

CRET cryptGetPublicKey( const CRYPT_KEYSET keyset,
						CRYPT_CONTEXT CPTR cryptContext,
						const CRYPT_KEYID_TYPE keyIDtype,
						const void CPTR keyID );
CRET cryptGetPrivateKey( const CRYPT_KEYSET keyset,
						 CRYPT_CONTEXT CPTR cryptContext,
						 const CRYPT_KEYID_TYPE keyIDtype,
						 const void CPTR keyID, const void CPTR password );

/* Add/delete a key to/from a keyset */

CRET cryptAddPublicKey( const CRYPT_KEYSET keyset,
						const CRYPT_CERTIFICATE certificate );
CRET cryptAddPrivateKey( const CRYPT_KEYSET keyset,
						 const CRYPT_HANDLE cryptKey,
						 const void CPTR password );
CRET cryptDeleteKey( const CRYPT_KEYSET keyset,
					 const CRYPT_KEYID_TYPE keyIDtype,
					 const void CPTR keyID );

/* Send a general query to a database keyset */

CRET cryptKeysetQuery( const CRYPT_KEYSET keyset, const char CPTR query );

/****************************************************************************
*																			*
*							Certificate Managment Functions					*
*																			*
****************************************************************************/

/* Create/destroy a certificate */

CRET cryptCreateCert( CRYPT_CERTIFICATE CPTR certificate,
					  const CRYPT_CERTTYPE_TYPE certType );
CRET cryptDestroyCert( const CRYPT_CERTIFICATE certificate );

/* Get/add/delete certificate components and extensions */

CRET cryptGetCertComponentNumeric( const CRYPT_HANDLE cryptHandle,
								   const CRYPT_CERTINFO_TYPE certInfoType,
								   int CPTR certInfo );
CRET cryptGetCertComponentString( const CRYPT_HANDLE cryptHandle,
								  const CRYPT_CERTINFO_TYPE certInfoType,
								  void CPTR certInfo, int CPTR certInfoLength );
CRET cryptAddCertComponentNumeric( const CRYPT_HANDLE cryptHandle,
								   const CRYPT_CERTINFO_TYPE certInfoType,
								   const int certInfo );
CRET cryptAddCertComponentString( const CRYPT_CERTIFICATE certificate,
								  const CRYPT_CERTINFO_TYPE certInfoType,
								  const void CPTR certInfo,
								  const int certInfoLength );
CRET cryptDeleteCertComponent( const CRYPT_CERTIFICATE certificate,
							   const CRYPT_CERTINFO_TYPE certInfoType );
CRET cryptGetCertExtension( const CRYPT_HANDLE cryptHandle,
							const char CPTR oid, int CPTR criticalFlag,
							void CPTR extension, int CPTR extensionLength );
CRET cryptAddCertExtension( const CRYPT_CERTIFICATE certificate,
							const char CPTR oid, const int criticalFlag,
							const void CPTR extension,
							const int extensionLength );
CRET cryptDeleteCertExtension( const CRYPT_CERTIFICATE certificate,
							   const char CPTR oid );

/* Sign/sig.check a certificate/certification request */

CRET cryptSignCert( const CRYPT_CERTIFICATE certificate,
					const CRYPT_CONTEXT signContext );
CRET cryptCheckCert( const CRYPT_CERTIFICATE certificate,
					 const CRYPT_HANDLE sigCheckKey );

/* Import/export a certificate/certification request */

CRET cryptImportCert( const void CPTR certObject,
					  CRYPT_CERTIFICATE CPTR certificate );
CRET cryptExportCert( void CPTR certObject, int CPTR certObjectLength,
					  const CRYPT_CERTFORMAT_TYPE certFormatType,
					  const CRYPT_CERTIFICATE certificate );

/****************************************************************************
*																			*
*							Data Enveloping Functions						*
*																			*
****************************************************************************/

/* Create/destroy an envelope */

CRET cryptCreateEnvelope( CRYPT_ENVELOPE CPTR envelope );
CRET cryptCreateDeenvelope( CRYPT_ENVELOPE CPTR envelope );
CRET cryptCreateEnvelopeEx( CRYPT_ENVELOPE CPTR envelope,
							const CRYPT_FORMAT_TYPE formatType,
							const int bufferSize );
CRET cryptCreateDeenvelopeEx( CRYPT_ENVELOPE CPTR envelope,
							  const int bufferSize );
CRET cryptDestroyEnvelope( const CRYPT_ENVELOPE envelope );

/* Envelope resource query functions (due to be replaced) */

CRET cryptGetResourceOwnerName( const CRYPT_ENVELOPE envelope, void CPTR name );

/* Get/add envelope components */

CRET cryptAddEnvComponentNumeric( const CRYPT_ENVELOPE envelope,
								  const CRYPT_ENVINFO_TYPE envInfoType,
								  const int envInfo );
CRET cryptAddEnvComponentString( const CRYPT_ENVELOPE envelope,
								 const CRYPT_ENVINFO_TYPE envInfoType,
								 const void CPTR envInfo,
								 const int envInfoLength );
CRET cryptGetEnvComponentNumeric( const CRYPT_ENVELOPE envelope,
								  const CRYPT_ENVINFO_TYPE envInfoType,
								  int CPTR envInfo );

/* Envelope/deenvelope data */

CRET cryptPushData( const CRYPT_ENVELOPE envelope, const void CPTR buffer,
					const int length, int CPTR bytesCopied );
CRET cryptPopData( const CRYPT_ENVELOPE envelope, void CPTR buffer,
				   const int length, int CPTR bytesCopied );

/****************************************************************************
*																			*
*								Crypto Device Functions						*
*																			*
****************************************************************************/

/* Open and close a device */

CRET cryptDeviceOpen( CRYPT_DEVICE CPTR device,
					  const CRYPT_DEVICE_TYPE deviceType,
					  const char CPTR name );
CRET cryptDeviceOpenEx( CRYPT_DEVICE CPTR device,
						const CRYPT_DEVICE_TYPE deviceType,
						const char CPTR param1, const char CPTR param2,
						const char CPTR param3, const char CPTR param4 );
CRET cryptDeviceClose( const CRYPT_DEVICE device );

/* Query a devices capabilities */

CRET cryptDeviceQueryCapability( const CRYPT_DEVICE device,
								 const CRYPT_ALGO cryptAlgo,
								 const CRYPT_MODE cryptMode,
								 CRYPT_QUERY_INFO CPTR cryptQueryInfo );

/* Create an encryption context via the device */

CRET cryptDeviceCreateContext( const CRYPT_DEVICE device,
							   CRYPT_CONTEXT CPTR cryptContext,
							   const CRYPT_ALGO cryptAlgo,
							   const CRYPT_MODE cryptMode );

/* Peform a control function on the device */

CRET cryptDeviceControl( const CRYPT_DEVICE device,
						 const CRYPT_DEVICECONTROL_TYPE controlType,
						 const void CPTR data, const int dataLength );
CRET cryptDeviceControlEx( const CRYPT_DEVICE device,
						   const CRYPT_DEVICECONTROL_TYPE controlType,
						   const void CPTR data1, const int data1Length,
						   const void CPTR data2, const int data2Length );

/****************************************************************************
*																			*
*								Secure Session Functions					*
*																			*
****************************************************************************/

/* Create and destroy a session */

CRET cryptCreateSession( CRYPT_SESSION CPTR session,
						 const CRYPT_FORMAT_TYPE sessionType );
CRET cryptDestroySession( const CRYPT_SESSION session );

/* Session management functions */

CRET cryptAddSessionComponentNumeric( const CRYPT_SESSION session,
									  const CRYPT_SESSINFO_TYPE sessionInfoType,
									  const int sessionInfo );

/* Add/get session datagrams to/from a session */

CRET cryptAddSessionData( void CPTR data, const CRYPT_SESSION session );
CRET cryptGetSessionData( void CPTR data, int CPTR dataLength,
						  const CRYPT_SESSIONDATA_TYPE sessionDataType,
						  const CRYPT_SESSION session );

/****************************************************************************
*																			*
*								Configuration Functions						*
*																			*
****************************************************************************/

/* Get numeric and string configuration options */

CRET cryptSetOptionNumeric( const CRYPT_OPTION_TYPE cryptOption,
							const int value );
CRET cryptSetOptionString( const CRYPT_OPTION_TYPE cryptOption,
						   const char CPTR value );

/* Set numeric and string configuration options */

CRET cryptGetOptionNumeric( const CRYPT_OPTION_TYPE cryptOption,
							int CPTR value );
CRET cryptGetOptionString( const CRYPT_OPTION_TYPE cryptOption,
						   char CPTR value, int CPTR valueLength );

/* Read and write configuration options */

CRET cryptReadOptions( void );
CRET cryptWriteOptions( void );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CAPI_DEFINED */

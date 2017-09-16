#ifndef _CRYPTLIB_DEFINED

#define _CRYPTLIB_DEFINED

/* Fixup for Windows support.  We need to include windows.h for various types
   and prototypes needed for DLL's.  In addition wincrypt.h defines some 
   values with the same names as cryptlib ones, so we need to check for this
   and issue a warning not to mix cryptlib with CryptoAPI (that's like taking
   a bank vault and making one side out of papier mache) */

#if ( defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 ) || \
	  defined( __WIN32__ ) ) && !defined( _SCCTK )
  #define WIN32_LEAN_AND_MEAN		/* Skip RPC, OLE, Multimedia, etc */
  #include <windows.h>

  #if defined( CRYPT_MODE_ECB )
	#error "cryptlib.h and wincrypt.h can't both be used at the same time due to conflicting type names"
  #endif /* Clash with wincrypt.h defines */
#endif /* ( _WINDOWS || WIN32 || _WIN32 || __WIN32__ ) && !_SCCTK */

/* Machine-dependant types to allow use in special library types such as
   DLL's.  Under Win32 we need to use the dllimport and dllexport directives
   for the DLL version of the library, so we define the type used for
   functions depending on whether we're being included via crypt.h or not */

#if ( defined( WIN32 ) || defined( _WIN32 ) || defined( __WIN32__ ) ) && \
	!( defined( STATIC_LIB ) || defined( _SCCTK ) )
  #define C_PTR	*					/* General pointer */
  #if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 )
	#ifdef _CRYPT_DEFINED
	  #define C_RET	int	_export _stdcall		/* BC++ DLL export ret.val.*/
	#else
	  #define C_RET	int	_export _stdcall		/* BC++ DLL import ret.val.*/
	#endif /* CRYPT_DEFINED */
  #else
	#ifdef _CRYPT_DEFINED
	  #define C_RET	__declspec( dllexport ) int	__stdcall	/* DLL export ret.val.*/
	#else
	  #define C_RET	__declspec( dllimport ) int	__stdcall	/* DLL import ret.val.*/
	#endif /* CRYPT_DEFINED */
  #endif /* BC++ vs VC++ DLL functions */
#elif defined( _WINDOWS )
  #define C_PTR	FAR *				/* DLL pointer */
  #define C_RET	int FAR PASCAL _export	/* DLL return value */
#else
  #define C_PTR	*					/* General pointer */
  #define C_RET	int					/* General return value */
#endif /* Windows vs everything else function types */

/* Symbolic defines to make it clearer how the function parameters behave */

#define C_IN	const				/* Input-only */
#define C_OUT						/* Output-only */
#define C_INOUT						/* Modified in-place */

/* Alongside the externally visible types, cryptlib also has various internal 
   types which are extended forms of the external types which are invisible 
   to the user (eg SignedPublicKeyAndChallenge == certRequest).  These can 
   only be used internally and are blocked by the security kernel, so they 
   can never be accessed from outside cryptlib (in fact for good measure 
   they're blocked before they even get to the kernel by preliminary range 
   checks in the API wrapper functions).  The only reason they're defined 
   here is because it's not possible to extend an enum outside the point 
   where it's originally defined */

/****************************************************************************
*																			*
*							Algorithm and Object Types						*
*																			*
****************************************************************************/

/* Algorithm and mode types */

typedef enum {						/* Algorithms */
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
	CRYPT_ALGO_SAFER,				/* SAFER/SAFER-SK - deprecated */
	CRYPT_ALGO_BLOWFISH,			/* Blowfish */
	CRYPT_ALGO_SKIPJACK,			/* Skipjack */
	CRYPT_ALGO_GOST,				/* GOST 28147 (not implemented yet) */

	/* Public-key encryption */
	CRYPT_ALGO_DH = 100,			/* Diffie-Hellman */
	CRYPT_ALGO_RSA,					/* RSA */
	CRYPT_ALGO_DSA,					/* DSA */
	CRYPT_ALGO_ELGAMAL,				/* ElGamal */
	CRYPT_ALGO_KEA,					/* KEA */

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
	   cryptQueryCapability(), we define the following boundary points for 
	   each algorithm class */
	CRYPT_ALGO_FIRST_CONVENTIONAL = CRYPT_ALGO_DES,
	CRYPT_ALGO_LAST_CONVENTIONAL = CRYPT_ALGO_DH - 1,
	CRYPT_ALGO_FIRST_PKC = CRYPT_ALGO_DH,
	CRYPT_ALGO_LAST_PKC = CRYPT_ALGO_MD2 - 1,
	CRYPT_ALGO_FIRST_HASH = CRYPT_ALGO_MD2,
	CRYPT_ALGO_LAST_HASH = CRYPT_ALGO_HMAC_MD5 - 1,
	CRYPT_ALGO_FIRST_MAC = CRYPT_ALGO_HMAC_MD5,
	CRYPT_ALGO_LAST_MAC = CRYPT_ALGO_HMAC_MD5 + 99	/* End of mac algo.range */
	} CRYPT_ALGO;

typedef enum {						/* Block cipher modes */
	CRYPT_MODE_NONE,				/* No encryption mode */
	CRYPT_MODE_ECB,					/* ECB */
	CRYPT_MODE_CBC,					/* CBC */
	CRYPT_MODE_CFB,					/* CFB */
	CRYPT_MODE_OFB,					/* OFB */
	CRYPT_MODE_LAST,				/* Last possible crypt mode value */
	} CRYPT_MODE;

/* Object subtypes */

typedef enum {						/* Keyset types */
	CRYPT_KEYSET_NONE,				/* No keyset type */
	CRYPT_KEYSET_FILE,				/* Generic flat file keyset (PGP, X.509) */
	CRYPT_KEYSET_HTTP,				/* Web page containing cert/CRL */
	CRYPT_KEYSET_LDAP,				/* LDAP directory service */
	CRYPT_KEYSET_SMARTCARD,			/* Smart card key carrier */
	CRYPT_KEYSET_ODBC,				/* Generic ODBC interface */
	CRYPT_KEYSET_MSQL,				/* mSQL RDBMS */
	CRYPT_KEYSET_MYSQL,				/* MySQL RDBMS */
	CRYPT_KEYSET_ORACLE,			/* Oracle RDBMS */
	CRYPT_KEYSET_POSTGRES,			/* Postgres RDBMS */
	CRYPT_KEYSET_LAST				/* Last possible keyset type */

#ifdef _CRYPT_DEFINED
	/* Useful defines used internally for range checking */
	, CRYPT_FIRST_RDBMS = CRYPT_KEYSET_ODBC,
	CRYPT_LAST_RDBMS = CRYPT_KEYSET_LAST - 1
#endif /* _CRYPT_DEFINED */
	} CRYPT_KEYSET_TYPE;

typedef enum {						/* Crypto device types */
	CRYPT_DEVICE_NONE,				/* No crypto device */
	CRYPT_DEVICE_FORTEZZA,			/* Fortezza card */
	CRYPT_DEVICE_PKCS11,			/* PKCS #11 crypto token */
	CRYPT_DEVICE_LAST				/* Last possible crypto device type */
	} CRYPT_DEVICE_TYPE;

typedef enum {						/* Certificate object types */
	CRYPT_CERTTYPE_NONE,			/* No certificate type */
	CRYPT_CERTTYPE_CERTIFICATE,		/* Certificate */
	CRYPT_CERTTYPE_ATTRIBUTE_CERT,	/* Attribute certificate */
	CRYPT_CERTTYPE_CERTCHAIN,		/* PKCS #7 certificate chain */
	CRYPT_CERTTYPE_CERTREQUEST,		/* PKCS #10 certification request */
	CRYPT_CERTTYPE_CRMF_REQUEST,	/* CRMF certification request */
	CRYPT_CERTTYPE_CRL,				/* CRL */
	CRYPT_CERTTYPE_CMS_ATTRIBUTES,	/* CMS attributes */
#ifdef _CRYPT_DEFINED
	/* Placeholders for possible future use */
	CRYPT_CERTTYPE_OCSP_REQUEST,
	CRYPT_CERTTYPE_OCSP_RESPONSE,
	/* Alongside the usual types we can also wind up with various 
	   certificate-bagging schemes such as cert chains and sequences which 
	   can't be exported in this format and therefore aren't visible to the 
	   user, but which need to be distinguished internally.  The following 
	   types are only visible internally */
	CRYPT_CERTTYPE_NS_CERTSEQUENCE,	/* Netscape cert sequence = cert chain */
	CRYPT_CERTTYPE_NS_SPKAC,		/* Netscape SPKAC = cert request */
	CRYPT_CERTTYPE_CMS_CERTSET,		/* CMS SET OF Certificate = cert chain */
	CRYPT_CERTTYPE_SSL_CERTCHAIN,	/* SSL certificate chain = cert chain */
#endif /* _CRYPT_DEFINED */
	CRYPT_CERTTYPE_LAST				/* Last possible cert.type */
#ifdef _CRYPT_DEFINED
	, CRYPT_CERTTYPE_LAST_EXTERNAL = CRYPT_CERTTYPE_NS_CERTSEQUENCE
#endif /* _CRYPT_DEFINED */
	} CRYPT_CERTTYPE_TYPE;

/****************************************************************************
*																			*
*								Attribute Types								*
*																			*
****************************************************************************/

/* Attribute types.  These are arranged in the following order:

	PROPERTY	- Object property
	ATTRIBUTE	- Generic attributes
	OPTION		- Global or object-specific config.option
	CTXINFO		- Context-specific attribute
	CERTINFO	- Certificate-specific attribute
	KEYSETINFO	- Keyset-specific attribute
	DEVINFO		- Device-specific attribute
	ENVINFO		- Envelope-specific attribute
	SESSINFO	- Session-specific attribute */

typedef enum {
	CRYPT_ATTRIBUTE_NONE,			/* Non-value */

	/* Used internally */
	CRYPT_PROPERTY_FIRST,

	/*********************/
	/* Object attributes */
	/*********************/

	/* Object properties */
	CRYPT_PROPERTY_HIGHSECURITY,	/* Owned+non-forwardable+locked */
	CRYPT_PROPERTY_OWNER,			/* Object owner */
	CRYPT_PROPERTY_FORWARDABLE,		/* No.of times object can be forwarded */
	CRYPT_PROPERTY_LOCKED,			/* Whether properties can be chged/read */
	CRYPT_PROPERTY_USAGECOUNT,		/* Usage count before object expires */
	CRYPT_PROPERTY_ENCRYPTONLY,		/* Whether context can be used only */
	CRYPT_PROPERTY_DECRYPTONLY,		/*   for encryption or decryption */
	CRYPT_PROPERTY_NONEXPORTABLE,	/* Whether key is nonexp.from context */

	/* Used internally */
	CRYPT_PROPERTY_LAST, CRYPT_GENERIC_FIRST,

	/* Extended error information */
	CRYPT_ATTRIBUTE_ERRORTYPE,		/* Type of last error */
	CRYPT_ATTRIBUTE_ERRORLOCUS,		/* Locus of last error */
	CRYPT_ATTRIBUTE_INT_ERRORCODE,	/* Low-level software-specific */
	CRYPT_ATTRIBUTE_INT_ERRORMESSAGE, /*   error code and message */
	
	/* Generic information */
	CRYPT_ATTRIBUTE_BUFFERSIZE,		/* Internal data buffer size */

	/* User internally */
	CRYPT_GENERIC_LAST, CRYPT_OPTION_FIRST = 100,

	/****************************/
	/* Configuration attributes */
	/****************************/

	/* cryptlib information (read-only) */
	CRYPT_OPTION_INFO_DESCRIPTION,	/* Text description */
	CRYPT_OPTION_INFO_COPYRIGHT,	/* Copyright notice */
	CRYPT_OPTION_INFO_MAJORVERSION,	/* Major release version */
	CRYPT_OPTION_INFO_MINORVERSION,	/* Minor release version */
	CRYPT_OPTION_INFO_STEPPING,		/* Release stepping */

	/* Encryption options */
	CRYPT_OPTION_ENCR_ALGO,			/* Encryption algorithm */
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

	/* CMS/SMIME options */
	CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,	/* Add default CMS attributes */
		CRYPT_OPTION_SMIME_DEFAULTATTRIBUTES = CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,

	/* HTTP keyset access options */
	CRYPT_OPTION_KEYS_HTTP_PROXY,		/* URL of web proxy */
	CRYPT_OPTION_KEYS_HTTP_TIMEOUT,		/* Timeout for read */

	/* LDAP keyset options */
	CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS,	/* Object class */
	CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE,	/* Object type to fetch */
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
	CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY,/* Use only hardware mechanisms */
	CRYPT_OPTION_DEVICE_SERIALRNG,		/* Serial-port-based RNG name */
	CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS,/* Serial RNG parameters */

	/* Session options */
	CRYPT_OPTION_SESSION_TIMEOUT,		/* Timeout for network accesses */

	/* Miscellaneous options */
	CRYPT_OPTION_MISC_FORCELOCK,	/* Whether to force memory locking */
	CRYPT_OPTION_MISC_ASYNCINIT,	/* Whether to init cryptlib async'ly */

	/* Config option status */
	CRYPT_OPTION_CONFIGCHANGED,		/* Whether in-mem.opts match on-disk ones */

	/* Used internally */
	CRYPT_OPTION_LAST, CRYPT_CTXINFO_FIRST = 1000,

	/**********************/
	/* Context attributes */
	/**********************/

	/* Algorithm and mode information */
	CRYPT_CTXINFO_ALGO,				/* Algorithm */
	CRYPT_CTXINFO_MODE,				/* Mode */
	CRYPT_CTXINFO_NAME_ALGO,		/* Algorithm name */
	CRYPT_CTXINFO_NAME_MODE,		/* Mode name */
	CRYPT_CTXINFO_KEYSIZE,			/* Key size in bytes */
	CRYPT_CTXINFO_BLOCKSIZE,		/* Block size */
	CRYPT_CTXINFO_IVSIZE,			/* IV size */
	CRYPT_CTXINFO_KEYING_ALGO,		/* Key processing algorithm */
	CRYPT_CTXINFO_KEYING_ITERATIONS,/* Key processing iterations */
	CRYPT_CTXINFO_KEYING_SALT,		/* Key processing salt */
	CRYPT_CTXINFO_KEYING_VALUE,		/* Value used to derive key */

	/* State information */
	CRYPT_CTXINFO_KEY,				/* Key */
	CRYPT_CTXINFO_KEY_COMPONENTS,	/* Public-key components */
	CRYPT_CTXINFO_IV,				/* IV */
	CRYPT_CTXINFO_HASHVALUE,		/* Hash value */

	/* Misc.information */
	CRYPT_CTXINFO_LABEL,			/* Label for private key */

	/* Used internally */
	CRYPT_CTXINFO_LAST, CRYPT_CERTINFO_FIRST = 2000,

	/**************************/
	/* Certificate attributes */
	/**************************/

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
	CRYPT_CERTINFO_TRUSTED_USAGE,	/* Usage which cert is trusted for */
	CRYPT_CERTINFO_TRUSTED_IMPLICIT,/* Whether cert is implicitly trusted */

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
	CRYPT_CERTINFO_COUNTRYNAME = CRYPT_CERTINFO_FIRST + 100,	/* countryName */
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
	CRYPT_CERTINFO_AUTHORITYINFOACCESS = CRYPT_CERTINFO_FIRST + 200,
	CRYPT_CERTINFO_AUTHORITYINFO_OCSP,	/* accessDescription.accessLocation */
	CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,	/* accessDescription.accessLocation */

	/* 1 3 36 8 3 1 */
	CRYPT_CERTINFO_SIGG_DATEOFCERTGEN,

	/* 1 3 36 8 3 2 */
	CRYPT_CERTINFO_SIGG_PROCURATION,
	CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY,	/* country */
	CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION,	/* typeOfSubstitution */
	CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR,	/* signingFor.thirdPerson */

	/* 1 3 36 8 3 4 */
	CRYPT_CERTINFO_SIGG_MONETARYLIMIT,
	CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY,	/* currency */
	CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT,	/* amount */
	CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT,	/* exponent */

	/* 1 3 36 8 3 8 */
	CRYPT_CERTINFO_SIGG_RESTRICTION,

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
	CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,	/* directoryService */
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
	CRYPT_CERTINFO_CMS_CONTENTTYPE = CRYPT_CERTINFO_FIRST + 500,

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

	/* Used internally */
	CRYPT_CERTINFO_LAST, CRYPT_KEYSETINFO_FIRST = 3000,

	/*********************/
	/* Keyset attributes */
	/*********************/

	CRYPT_KEYSETINFO_QUERY,			/* Keyset query */

	/* Used internally */
	CRYPT_KEYSETINFO_LAST, CRYPT_DEVINFO_FIRST = 4000,

	/*********************/
	/* Device attributes */
	/*********************/

	CRYPT_DEVINFO_INITIALISE,	/* Initialise device for use */
		CRYPT_DEVINFO_INITIALIZE = CRYPT_DEVINFO_INITIALISE,
	CRYPT_DEVINFO_AUTHENT_USER,	/* Authenticate user to device */
	CRYPT_DEVINFO_AUTHENT_SUPERVISOR,	/* Authenticate supervisor to dev.*/
	CRYPT_DEVINFO_SET_AUTHENT_USER,	/* Set user authent.value */
	CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR,	/* Set supervisor auth.val.*/
	CRYPT_DEVINFO_ZEROISE,	/* Zeroise device */
		CRYPT_DEVINFO_ZEROIZE = CRYPT_DEVINFO_ZEROISE,

	/* Used internally */
	CRYPT_DEVINFO_LAST, CRYPT_ENVINFO_FIRST = 5000,

	/***********************/
	/* Envelope attributes */
	/***********************/

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
	CRYPT_ENVINFO_RECIPIENT,		/* Recipient email address */
	CRYPT_ENVINFO_PUBLICKEY,		/* PKC encryption key */
	CRYPT_ENVINFO_PRIVATEKEY,		/* PKC decryption key */
	CRYPT_ENVINFO_PRIVATEKEY_LABEL,	/* Label of PKC decryption key */
	CRYPT_ENVINFO_ORIGINATOR,		/* Originator info/key */
	CRYPT_ENVINFO_SESSIONKEY,		/* Session key */
	CRYPT_ENVINFO_HASH,				/* Hash algorithm */
	CRYPT_ENVINFO_MAC,				/* MAC key */
	CRYPT_ENVINFO_TIMESTAMP_AUTHORITY,	/* Timestamp authority */

	/* Keysets used to retrieve keys needed for enveloping/deenveloping */
	CRYPT_ENVINFO_KEYSET_SIGCHECK,	/* Signature check keyset */
	CRYPT_ENVINFO_KEYSET_ENCRYPT,	/* PKC encryption keyset */
	CRYPT_ENVINFO_KEYSET_DECRYPT,	/* PKC decryption keyset */

	/* Used internally */
	CRYPT_ENVINFO_LAST, CRYPT_SESSINFO_FIRST = 6000,

	/**********************/
	/* Session attributes */
	/**********************/

	/* Pseudo-information on a session or meta-information which is used to
	   control the way a session is managed */

	/* Pseudo-information about the session */
	CRYPT_SESSINFO_ACTIVE,			/* Whether session is active */

	/* Security-related information */
	CRYPT_SESSINFO_USERNAME,		/* User name */
	CRYPT_SESSINFO_PASSWORD,		/* Password */

	/* Client/server information */
	CRYPT_SESSINFO_SERVER,			/* Server name */
	CRYPT_SESSINFO_SERVER_PORT,		/* Server port number */

	/* Protocol-specific information */
	CRYPT_SESSINFO_CMP_STATUS,		/* CMP status value */
	CRYPT_SESSINFO_CMP_STATUSINFO,	/* CMP extended status info */
	CRYPT_SESSINFO_CMP_PASSWORD_ID,	/* CMP password identifier */
	CRYPT_SESSINFO_CMP_CA_NAME,		/* CMP cert issuer name */

	/* Used internally for range checking */
	CRYPT_SESSINFO_LAST, CRYPT_ATTRIBUTE_LAST = CRYPT_SESSINFO_LAST

#ifdef _CRYPT_DEFINED
	/***********************/
	/* Internal attributes */
	/***********************/

	/* The following attributes are only visible internally and are protected
	   from any external access by the kernel (and for good measure by checks
	   in other places as well).  The two attributes 
	   CRYPT_IATTRIBUTE_PUBLICKEY and CRYPT_IATTRIBUTE_SPKI are actually the 
	   same thing, the difference is that the former is write-only for 
	   contexts and the latter is read-only for certificates.  Because a 
	   single object can act as both a context and a cert, having two 
	   explicitly different attribute names makes things less confusing */
	, CRYPT_IATTRIBUTE_FIRST = 7000, 
	CRYPT_IATTRIBUTE_TYPE,			/* Object type */
	CRYPT_IATTRIBUTE_STATUS,		/* Object status */
	CRYPT_IATTRIBUTE_INTERNAL,		/* Object internal flag */
	CRYPT_IATTRIBUTE_ACTIONPERMS,	/* Object action permissions */
	CRYPT_IATTRIBUTE_INITIALISED,	/* Object = inited (in high state) */
	CRYPT_IATTRIBUTE_KEYSIZE,		/* Ctx: Key size (written to non-native ctxs) */
	CRYPT_IATTRIBUTE_KEYID,			/* Ctx: Key ID */
	CRYPT_IATTRIBUTE_DOMAINPARAMS,	/* Ctx: Key agreement domain parameters */
	CRYPT_IATTRIBUTE_PUBLICVALUE,	/* Ctx: Key agreement public value */
	CRYPT_IATTRIBUTE_PUBLICKEY,		/* Ctx: Encoded SubjectPublicKeyInfo */
	CRYPT_IATTRIBUTE_SSH_PUBLICKEY,	/* Ctx: SSH-format public key */
	CRYPT_IATTRIBUTE_DEVICEOBJECT,	/* Ctx: Device object handle */
	CRYPT_IATTRIBUTE_SUBJECT,		/* Cert: SubjectName */
	CRYPT_IATTRIBUTE_ISSUER,		/* Cert: IssuerName */
	CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,	/* Cert: IssuerAndSerial */
	CRYPT_IATTRIBUTE_CERTSET,		/* Cert: SET OF cert in chain */
	CRYPT_IATTRIBUTE_SPKI,			/* Cert: Encoded SubjectPublicKeyInfo */
	CRYPT_IATTRIBUTE_ENC_CERT,		/* Cert: Encoded certificate */
	CRYPT_IATTRIBUTE_ENC_CERTCHAIN,	/* Cert: Encoded cert.chain */
	CRYPT_IATTRIBUTE_ENC_CMSATTR,	/* Cert: Encoded CMS signed attrs.*/
	CRYPT_IATTRIBUTE_TEXT_CERT,		/* Cert: base64-encoded certificate */
	CRYPT_IATTRIBUTE_TEXT_CERTCHAIN,/* Cert: base64-encoded cert.chain */
	CRYPT_IATTRIBUTE_RANDOM,		/* Dev: Random data */
	CRYPT_IATTRIBUTE_RANDOM_NZ,		/* Dev: Nonzero random data */
	CRYPT_IATTRIBUTE_RANDOM_QUALITY,/* Dev: Quality of random data */
	CRYPT_IATTRIBUTE_CONFIGDATA,	/* Keyset: Encoded config information */
	CRYPT_IATTRIBUTE_LAST,

	/* Subrange values used internally for range checking.  Because there are
	   so many cert attributes, we break them down into blocks to minimise 
	   the number of values which change if a new one is added halfway 
	   through */
	CRYPT_CERTINFO_FIRST_CERTINFO = CRYPT_CERTINFO_SELFSIGNED - 1,
	CRYPT_CERTINFO_LAST_CERTINFO = CRYPT_CERTINFO_REVOCATIONDATE + 1,
	CRYPT_CERTINFO_FIRST_NAME = CRYPT_CERTINFO_COUNTRYNAME - 1,
	CRYPT_CERTINFO_LAST_NAME = CRYPT_CERTINFO_REGISTEREDID + 1,
	CRYPT_CERTINFO_FIRST_EXTENSION = CRYPT_CERTINFO_AUTHORITYINFOACCESS - 1,
	CRYPT_CERTINFO_LAST_EXTENSION = CRYPT_CERTINFO_SET_TUNNELINGALGID + 1,
	CRYPT_CERTINFO_FIRST_CMS = CRYPT_CERTINFO_CMS_CONTENTTYPE - 1,
	CRYPT_CERTINFO_LAST_CMS = CRYPT_CERTINFO_LAST,

	/* Older values used by the cert code - due to be phased out */
	CRYPT_FIRST_PSEUDOINFO = CRYPT_CERTINFO_SELFSIGNED,
	CRYPT_LAST_PSEUDOINFO = CRYPT_CERTINFO_TRUSTED_IMPLICIT,
	CRYPT_FIRST_CERTINFO = CRYPT_CERTINFO_SERIALNUMBER,
	CRYPT_LAST_CERTINFO = CRYPT_CERTINFO_REVOCATIONDATE,
	CRYPT_FIRST_DN = CRYPT_CERTINFO_COUNTRYNAME,
	CRYPT_LAST_DN = CRYPT_CERTINFO_COMMONNAME,
	CRYPT_FIRST_GENERALNAME = CRYPT_CERTINFO_OTHERNAME_TYPEID,
	CRYPT_LAST_GENERALNAME = CRYPT_CERTINFO_REGISTEREDID,
	CRYPT_FIRST_EXTENSION = CRYPT_CERTINFO_AUTHORITYINFOACCESS,
	CRYPT_LAST_EXTENSION = CRYPT_CERTINFO_SET_TUNNELINGALGID,
	CRYPT_FIRST_CMS = CRYPT_CERTINFO_CMS_CONTENTTYPE,
	CRYPT_LAST_CMS = CRYPT_CERTINFO_LAST - 1
#endif /* _CRYPT_DEFINED */
	} CRYPT_ATTRIBUTE_TYPE;

/****************************************************************************
*																			*
*						Attribute Subtypes and Related Values				*
*																			*
****************************************************************************/

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

/* Flags for the SET certificate-type extension */

#define CRYPT_SET_CERTTYPE_CARD				0x001
#define CRYPT_SET_CERTTYPE_MER				0x002
#define CRYPT_SET_CERTTYPE_PGWY				0x004
#define CRYPT_SET_CERTTYPE_CCA				0x008
#define CRYPT_SET_CERTTYPE_MCA				0x010
#define CRYPT_SET_CERTTYPE_PCA				0x020
#define CRYPT_SET_CERTTYPE_GCA				0x040
#define CRYPT_SET_CERTTYPE_BCA				0x080
#define CRYPT_SET_CERTTYPE_RCA				0x100
#define CRYPT_SET_CERTTYPE_ACQ				0x200
#define CRYPT_SET_CERTTYPE_LAST				0x400	/* Last possible value */

/* CMS contentType values */

typedef enum { CRYPT_CONTENT_NONE, CRYPT_CONTENT_DATA,
			   CRYPT_CONTENT_SIGNEDDATA, CRYPT_CONTENT_ENVELOPEDDATA,
			   CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
			   CRYPT_CONTENT_DIGESTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA,
			   CRYPT_CONTENT_COMPRESSEDDATA, 
			   CRYPT_CONTENT_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_LAST
			   } CRYPT_CONTENT_TYPE;

/* ESS securityClassification codes */

enum { CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_UNCLASSIFIED,
	   CRYPT_CLASSIFICATION_RESTRICTED, CRYPT_CLASSIFICATION_CONFIDENTIAL,
	   CRYPT_CLASSIFICATION_SECRET, CRYPT_CLASSIFICATION_TOP_SECRET,
	   CRYPT_CLASSIFICATION_LAST = 255 };

/* CMP status and extended status info values */

enum { CRYPT_CMPSTATUS_OK, CRYPT_CMPSTATUS_GRANTED = CRYPT_CMPSTATUS_OK,
	   CRYPT_CMPSTATUS_GRANTEDWITHMODS, CRYPT_CMPSTATUS_REJECTION,
	   CRYPT_CMPSTATUS_WAITING, CRYPT_CMPSTATUS_REVOCATIONWARNING,
	   CRYPT_CMPSTATUS_REVOCATIONNOTIFICATION, 
	   CRYPT_CMPSTATUS_KEYUPDATEWARNING, CRYPT_CMPSTATUS_LAST };

#define CRYPT_CMPSTATUS_EXT_BADALG			0x001
#define CRYPT_CMPSTATUS_EXT_BADMESSAGECHECK	0x002
#define CRYPT_CMPSTATUS_EXT_BADREQUEST		0x004
#define CRYPT_CMPSTATUS_EXT_BADTIME			0x008
#define CRYPT_CMPSTATUS_EXT_BADCERTID		0x010
#define CRYPT_CMPSTATUS_EXT_BADDATAFORMAT	0x020
#define CRYPT_CMPSTATUS_EXT_WRONGAUTHORITY	0x040
#define CRYPT_CMPSTATUS_EXT_INCORRECTDATA	0x080
#define CRYPT_CMPSTATUS_EXT_MISSINGTIMESTAMP 0x100
#define CRYPT_CMPSTATUS_EXT_BADPOP			0x200
#define CRYPT_CMPSTATUS_EXT_LAST			0x400	/* Last possible value */

/* The certificate export format type, which defines the format in which a
   certificate object is exported */

typedef enum {
	CRYPT_CERTFORMAT_NONE,			/* No certificate format */
	CRYPT_CERTFORMAT_CERTIFICATE,	/* DER-encoded certificate */
	CRYPT_CERTFORMAT_CERTCHAIN,		/* PKCS #7 certificate chain */
	CRYPT_CERTFORMAT_TEXT_CERTIFICATE,	/* base-64 wrapped cert */
	CRYPT_CERTFORMAT_TEXT_CERTCHAIN,	/* base-64 wrapped cert chain */
	CRYPT_CERTFORMAT_LAST			/* Last possible cert.format type */
#ifdef _CRYPT_DEFINED	
	/* No longer used externally since it's an MUA/MTA function - 7/1/00 */
	, CRYPT_ICERTFORMAT_SMIME_CERTIFICATE /* S/MIME cert.request or cert chain */
#endif /* CRYPT_DEFINED */
	} CRYPT_CERTFORMAT_TYPE;

/* Key ID types */

typedef enum {
	CRYPT_KEYID_NONE,				/* No key ID type */
	CRYPT_KEYID_NAME,				/* Key owner name */
	CRYPT_KEYID_EMAIL,				/* Key owner email address */
#ifdef _CRYPT_DEFINED
	/* Internal key ID types */
	CRYPT_IKEYID_KEYID,				/* SubjectKeyIdentifier */
	CRYPT_IKEYID_ISSUERID,			/* Hashed issuerAndSerialNumber */
	CRYPT_IKEYID_ISSUERANDSERIALNUMBER,	/* X.509 issuer and serial number */
#endif /* _CRYPT_DEFINED */
	CRYPT_KEYID_LAST				/* Last possible key ID type */
#ifdef _CRYPT_DEFINED
	, CRYPT_KEYID_LAST_EXTERNAL = CRYPT_IKEYID_KEYID/* Last external key ID */
#endif /* _CRYPT_DEFINED */
	} CRYPT_KEYID_TYPE;

/* Data format types */

typedef enum {
	CRYPT_FORMAT_NONE,				/* No format type */
	CRYPT_FORMAT_AUTO,				/* Deenv, auto-determine type */
	CRYPT_FORMAT_CRYPTLIB,			/* Envelope: cryptlib native format */
	CRYPT_FORMAT_CMS,				/* Envelope: PKCS #7 / CMS / S/MIME fmt.*/
		CRYPT_FORMAT_PKCS7 = CRYPT_FORMAT_CMS,
	CRYPT_FORMAT_SMIME,				/* Envelope: As CMS with MSG-style behaviour */
	CRYPT_FORMAT_PGP,				/* Envelope: PGP format */
	CRYPT_FORMAT_SSH,				/* Session: SSH */
	CRYPT_FORMAT_SSL,				/* Session: SSL 3.0 */
	CRYPT_FORMAT_TLS,				/* Session: TLS */
	CRYPT_FORMAT_CMP,				/* Session: PKIX CMP */
	CRYPT_FORMAT_LAST				/* Last possible format type */
#ifdef _CRYPT_DEFINED
	, CRYPT_FORMAT_FIRST_ENVELOPE = CRYPT_FORMAT_AUTO,
	CRYPT_FORMAT_LAST_ENVELOPE = CRYPT_FORMAT_PGP,
	CRYPT_FORMAT_FIRST_SESSION = CRYPT_FORMAT_SSH,
	CRYPT_FORMAT_LAST_SESSION = CRYPT_FORMAT_CMP
#endif /* _CRYPT_DEFINED */
	} CRYPT_FORMAT_TYPE;

/* The encryption object types */

typedef enum {
	CRYPT_OBJECT_NONE,				/* No object type */
	CRYPT_OBJECT_ENCRYPTED_KEY,		/* Conventionally encrypted key */
	CRYPT_OBJECT_PKCENCRYPTED_KEY,	/* PKC-encrypted key */
	CRYPT_OBJECT_KEYAGREEMENT,		/* Key agreement information */
	CRYPT_OBJECT_SIGNATURE,			/* Signature */
	CRYPT_OBJECT_LAST				/* Last possible object type */
	} CRYPT_OBJECT_TYPE;

/* Object/attribute error type information */

typedef enum {
	CRYPT_ERRTYPE_NONE,				/* No error information */
	CRYPT_ERRTYPE_ATTR_SIZE,		/* Attribute data too small or large */
	CRYPT_ERRTYPE_ATTR_VALUE,		/* Attribute value is invalid */
	CRYPT_ERRTYPE_ATTR_ABSENT,		/* Required attribute missing */
	CRYPT_ERRTYPE_ATTR_PRESENT,		/* Non-allowed attribute present */
	CRYPT_ERRTYPE_CONSTRAINT,		/* Cert: Constraint violation in object */
	CRYPT_ERRTYPE_ISSUERCONSTRAINT,	/* Cert: Constraint viol.in issuing cert */
	CRYPT_ERRTYPE_LAST				/* Last possible error info type */
	} CRYPT_ERRTYPE_TYPE;

/****************************************************************************
*																			*
*								General Constants							*
*																			*
****************************************************************************/

/* The maximum user key size - 2048 bits */

#define CRYPT_MAX_KEYSIZE		256

/* The maximum IV size - 256 bits */

#define CRYPT_MAX_IVSIZE		32

/* The maximum public-key component size - 4096 bits */

#define CRYPT_MAX_PKCSIZE		512

/* The maximum hash size - 256 bits */

#define CRYPT_MAX_HASHSIZE		32

/* The maximum size of a text string (eg key owner name) */

#define CRYPT_MAX_TEXTSIZE		64

/* A magic value indicating that the default setting for this parameter
   should be used */

#define CRYPT_USE_DEFAULT		-10

/* A magic value for unused parameters */

#define CRYPT_UNUSED			-11

/* Whether the PKC key is a public or private key */

#define CRYPT_KEYTYPE_PRIVATE	0
#define CRYPT_KEYTYPE_PUBLIC	1

/* The type of information polling to perform to get random seed information */

#define CRYPT_RANDOM_FASTPOLL	-10
#define CRYPT_RANDOM_SLOWPOLL	-11

/* Cursor positioning codes for certificate/CRL extensions */

#define CRYPT_CURSOR_FIRST		-20
#define CRYPT_CURSOR_PREVIOUS	-21
#define CRYPT_CURSOR_NEXT		-22
#define CRYPT_CURSOR_LAST		-23

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
	/* Algorithm information */
	char algoName[ CRYPT_MAX_TEXTSIZE ];/* The algorithm name */
	int blockSize;					/* The block size of the algorithm */
	int minKeySize;					/* Minimum key size in bytes */
	int keySize;					/* Recommended key size in bytes */
	int maxKeySize;					/* Maximum key size in bytes */
	} CRYPT_QUERY_INFO;

/* Results returned from the encryption object query.  These provide
   information on the objects created by cryptExportKey()/
   cryptCreateSignature() */

typedef struct {
	/* The object type */
	CRYPT_OBJECT_TYPE objectType;	/* The object type */

	/* The encryption algorithm and mode */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */

	/* The hash algorithm for Signature objects */
	CRYPT_ALGO hashAlgo;			/* Hash algorithm */

	/* The salt for derived keys */
	unsigned char salt[ CRYPT_MAX_HASHSIZE ];
	int saltSize;
	} CRYPT_OBJECT_INFO;

/* Key information for the public-key encryption algorithms.  These fields
   are not accessed directly, but can be manipulated with the init/set/
   destroyComponents() macros */

typedef struct {
	/* Status information */
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
	} CRYPT_PKCINFO_DLP;

/* Macros to initialise and destroy the structure which stores the components
   of a public key */

#define cryptInitComponents( componentInfo, componentKeyType ) \
	{ memset( componentInfo, 0, sizeof( *componentInfo ) ); \
	  componentInfo##->isPublicKey = ( componentKeyType ? TRUE : FALSE ); }

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

#define CRYPT_OK					0	/* No error */

/* Error in parameters passed to function */

#define CRYPT_ERROR_PARAM1		-1	/* Bad argument, parameter 1 */
#define CRYPT_ERROR_PARAM2		-2	/* Bad argument, parameter 2 */
#define CRYPT_ERROR_PARAM3		-3	/* Bad argument, parameter 3 */
#define CRYPT_ERROR_PARAM4		-4	/* Bad argument, parameter 4 */
#define CRYPT_ERROR_PARAM5		-5	/* Bad argument, parameter 5 */
#define CRYPT_ERROR_PARAM6		-6	/* Bad argument, parameter 6 */
#define CRYPT_ERROR_PARAM7		-7	/* Bad argument, parameter 7 */

/* Errors due to insufficient resources */

#define CRYPT_ERROR_MEMORY		-10	/* Out of memory */
#define CRYPT_ERROR_NOTINITED	-11	/* Data has not been initialised */
#define CRYPT_ERROR_INITED		-12	/* Data has already been init'd */
#define CRYPT_ERROR_NOSECURE	-13	/* Opn.not avail.at requested sec.level */
#define CRYPT_ERROR_RANDOM		-14	/* No reliable random data available */
#define CRYPT_ERROR_FAILED		-15	/* Operation failed */

/* Security violations */

#define CRYPT_ERROR_NOTAVAIL	-20	/* This type of opn.not available */
#define CRYPT_ERROR_PERMISSION	-21	/* No permiss.to perform this operation */
#define CRYPT_ERROR_WRONGKEY	-22	/* Incorrect key used to decrypt data */
#define CRYPT_ERROR_INCOMPLETE	-23	/* Operation incomplete/still in progress */
#define CRYPT_ERROR_COMPLETE	-24	/* Operation complete/can't continue */
#define CRYPT_ERROR_BUSY		-25	/* Resource in use by async operation */
#define CRYPT_ERROR_INVALID		-26	/* Invalid/inconsistent information */
#define CRYPT_ERROR_SIGNALLED	-27	/* Resource destroyed by extnl.event */

/* High-level function errors */

#define CRYPT_ERROR_OVERFLOW	-30	/* Resources/space exhausted */
#define CRYPT_ERROR_UNDERFLOW	-31	/* Not enough data available */
#define CRYPT_ERROR_BADDATA		-32	/* Bad/unrecognised data format */
#define CRYPT_ERROR_SIGNATURE	-33	/* Signature/integrity check failed */

/* Data access function errors */

#define CRYPT_ERROR_OPEN		-40	/* Cannot open object */
#define CRYPT_ERROR_READ		-41	/* Cannot read item from object */
#define CRYPT_ERROR_WRITE		-42	/* Cannot write item to object */
#define CRYPT_ERROR_NOTFOUND	-43	/* Requested item not found in object */
#define CRYPT_ERROR_DUPLICATE	-44	/* Item already present in object */

/* Data enveloping errors */

#define CRYPT_ENVELOPE_RESOURCE	-50	/* Need resource to proceed */

/* Macros to examine return values */

#define cryptStatusError( status )	( ( status ) < CRYPT_OK )
#define cryptStatusOK( status )		( ( status ) == CRYPT_OK )

/****************************************************************************
*																			*
*									General Functions						*
*																			*
****************************************************************************/

/* The following is necessary to stop C++ name mangling */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Initialise and shut down cryptlib */

C_RET cryptInit( void );
C_RET cryptInitEx( void );
C_RET cryptEnd( void );

/* Query cryptlibs capabilities */

C_RET cryptQueryCapability( C_IN CRYPT_ALGO cryptAlgo,
							C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo );

/* Create and destroy an encryption context */

C_RET cryptCreateContext( C_OUT CRYPT_CONTEXT C_PTR cryptContext,
						  C_IN CRYPT_ALGO cryptAlgo );
C_RET cryptDestroyContext( C_IN CRYPT_CONTEXT cryptContext );

/* Generic "destroy an object" function */

C_RET cryptDestroyObject( C_IN CRYPT_HANDLE cryptObject );

/* Generate a key into a context */

C_RET cryptGenerateKey( C_IN CRYPT_CONTEXT cryptContext );
C_RET cryptGenerateKeyEx( C_IN CRYPT_CONTEXT cryptContext, 
						  C_IN int keyLength );
C_RET cryptGenerateKeyAsync( C_IN CRYPT_CONTEXT cryptContext );
C_RET cryptGenerateKeyAsyncEx( C_IN CRYPT_CONTEXT cryptContext,
							   C_IN int keyLength );
C_RET cryptAsyncQuery( C_IN CRYPT_CONTEXT cryptContext );
C_RET cryptAsyncCancel( C_IN CRYPT_CONTEXT cryptContext );

/* Encrypt/decrypt/hash a block of memory */

C_RET cryptEncrypt( C_IN CRYPT_CONTEXT cryptContext, C_INOUT void C_PTR buffer,
					C_IN int length );
C_RET cryptDecrypt( C_IN CRYPT_CONTEXT cryptContext, C_INOUT void C_PTR buffer,
					C_IN int length );

/* Get/set/delete attribute functions */

C_RET cryptSetAttribute( C_IN CRYPT_HANDLE cryptHandle, 
						 C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
						 C_IN int value );
C_RET cryptSetAttributeString( C_IN CRYPT_HANDLE cryptHandle, 
							   C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
							   C_IN void C_PTR value, C_IN int valueLength );
C_RET cryptGetAttribute( C_IN CRYPT_HANDLE cryptHandle, 
						 C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
						 C_OUT int C_PTR value );
C_RET cryptGetAttributeString( C_IN CRYPT_HANDLE cryptHandle, 
							   C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
							   C_OUT void C_PTR value, 
							   C_OUT int C_PTR valueLength );
C_RET cryptDeleteAttribute( C_IN CRYPT_HANDLE cryptHandle, 
							C_IN CRYPT_ATTRIBUTE_TYPE attributeType );

/* Oddball functions: Add random data to the pool, query an encoded signature 
   or key data.  These are due to be replaced once a suitable alternative can
   be found */

C_RET cryptAddRandom( C_IN void C_PTR randomData, C_IN int randomDataLength );
C_RET cryptQueryObject( C_IN void C_PTR objectData,
					    C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo );

/****************************************************************************
*																			*
*							Mid-level Encryption Functions					*
*																			*
****************************************************************************/

/* Export and import an encrypted session key */

C_RET cryptExportKey( C_OUT void C_PTR encryptedKey, 
					  C_OUT int C_PTR encryptedKeyLength,
					  C_IN CRYPT_HANDLE exportKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext );
C_RET cryptExportKeyEx( C_OUT void C_PTR encryptedKey, 
						C_OUT int C_PTR encryptedKeyLength,
						C_IN CRYPT_FORMAT_TYPE formatType,
						C_IN CRYPT_HANDLE exportKey,
						C_IN CRYPT_CONTEXT sessionKeyContext );
C_RET cryptImportKey( C_IN void C_PTR encryptedKey, 
					  C_IN CRYPT_CONTEXT importKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext );
C_RET cryptImportKeyEx( C_IN void C_PTR encryptedKey, 
						C_IN CRYPT_CONTEXT importKey,
						C_IN CRYPT_CONTEXT sessionKeyContext );

/* Create and check a digital signature */

C_RET cryptCreateSignature( C_OUT void C_PTR signature, 
							C_OUT int C_PTR signatureLength,
							C_IN CRYPT_CONTEXT signContext,
							C_IN CRYPT_CONTEXT hashContext );
C_RET cryptCreateSignatureEx( C_OUT void C_PTR signature, 
							  C_OUT int C_PTR signatureLength,
							  C_IN CRYPT_FORMAT_TYPE formatType,
							  C_IN CRYPT_CONTEXT signContext,
							  C_IN CRYPT_CONTEXT hashContext,
							  C_IN CRYPT_CERTIFICATE extraData );
C_RET cryptCheckSignature( C_IN void C_PTR signature,
						   C_IN CRYPT_HANDLE sigCheckKey,
						   C_IN CRYPT_CONTEXT hashContext );
C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
							 C_IN CRYPT_HANDLE sigCheckKey,
							 C_IN CRYPT_CONTEXT hashContext,
							 C_OUT CRYPT_HANDLE C_PTR extraData );

/****************************************************************************
*																			*
*									Keyset Functions						*
*																			*
****************************************************************************/

/* Open and close a keyset */

C_RET cryptKeysetOpen( C_OUT CRYPT_KEYSET C_PTR keyset, 
					   C_IN CRYPT_KEYSET_TYPE keysetType,
					   C_IN char C_PTR name, C_IN CRYPT_KEYOPT_TYPE options );
C_RET cryptKeysetOpenEx( C_OUT CRYPT_KEYSET C_PTR keyset, 
						 C_IN CRYPT_KEYSET_TYPE keysetType,
						 C_IN char C_PTR name, C_IN char C_PTR param1,
						 C_IN char C_PTR param2, C_IN char C_PTR param3,
						 C_IN CRYPT_KEYOPT_TYPE options );
C_RET cryptKeysetClose( C_IN CRYPT_KEYSET keyset );

/* Get a key from a keyset */

C_RET cryptGetPublicKey( C_IN CRYPT_KEYSET keyset,
						 C_OUT CRYPT_CONTEXT C_PTR cryptContext,
						 C_IN CRYPT_KEYID_TYPE keyIDtype,
						 C_IN void C_PTR keyID );
C_RET cryptGetPrivateKey( C_IN CRYPT_KEYSET keyset,
						  C_OUT CRYPT_CONTEXT C_PTR cryptContext,
						  C_IN CRYPT_KEYID_TYPE keyIDtype,
						  C_IN void C_PTR keyID, C_IN void C_PTR password );

/* Add/delete a key to/from a keyset */

C_RET cryptAddPublicKey( C_IN CRYPT_KEYSET keyset,
						 C_IN CRYPT_CERTIFICATE certificate );
C_RET cryptAddPrivateKey( C_IN CRYPT_KEYSET keyset,
						  C_IN CRYPT_HANDLE cryptKey,
						  C_IN void C_PTR password );
C_RET cryptDeleteKey( C_IN CRYPT_KEYSET keyset,
					  C_IN CRYPT_KEYID_TYPE keyIDtype,
					  C_IN void C_PTR keyID );

/****************************************************************************
*																			*
*								Certificate Functions						*
*																			*
****************************************************************************/

/* Create/destroy a certificate */

C_RET cryptCreateCert( C_OUT CRYPT_CERTIFICATE C_PTR certificate,
					   C_IN CRYPT_CERTTYPE_TYPE certType );
C_RET cryptDestroyCert( C_IN CRYPT_CERTIFICATE certificate );

/* Get/add/delete certificate extensions */

C_RET cryptGetCertExtension( C_IN CRYPT_HANDLE cryptHandle,
							 C_IN char C_PTR oid, 
							 C_OUT int C_PTR criticalFlag,
							 C_OUT void C_PTR extension, 
							 C_OUT int C_PTR extensionLength );
C_RET cryptAddCertExtension( C_IN CRYPT_CERTIFICATE certificate,
							 C_IN char C_PTR oid, C_IN int criticalFlag,
							 C_IN void C_PTR extension, 
							 C_IN int extensionLength );
C_RET cryptDeleteCertExtension( C_IN CRYPT_CERTIFICATE certificate,
							    C_IN char C_PTR oid );

/* Sign/sig.check a certificate/certification request */

C_RET cryptSignCert( C_IN CRYPT_CERTIFICATE certificate,
					 C_IN CRYPT_CONTEXT signContext );
C_RET cryptCheckCert( C_IN CRYPT_CERTIFICATE certificate,
					  C_IN CRYPT_HANDLE sigCheckKey );

/* Import/export a certificate/certification request */

C_RET cryptImportCert( C_IN void C_PTR certObject, 
					   C_IN int certObjectLength,
					   C_OUT CRYPT_CERTIFICATE C_PTR certificate );
C_RET cryptExportCert( C_OUT void C_PTR certObject, 
					   C_OUT int C_PTR certObjectLength,
					   C_IN CRYPT_CERTFORMAT_TYPE certFormatType,
					   C_IN CRYPT_CERTIFICATE certificate );

/****************************************************************************
*																			*
*							Envelope and Session Functions					*
*																			*
****************************************************************************/

/* Create/destroy an envelope */

C_RET cryptCreateEnvelope( C_OUT CRYPT_ENVELOPE C_PTR envelope,
						   C_IN CRYPT_FORMAT_TYPE formatType );
C_RET cryptDestroyEnvelope( C_IN CRYPT_ENVELOPE envelope );

/* Create/destroy a session */

C_RET cryptCreateSession( C_OUT CRYPT_SESSION C_PTR session,
						  C_IN CRYPT_FORMAT_TYPE formatType );
C_RET cryptDestroySession( C_IN CRYPT_SESSION session );

/* Add/remove data to/from and envelope or session */

C_RET cryptPushData( C_IN CRYPT_HANDLE envelope, C_IN void C_PTR buffer,
					 C_IN int length, C_OUT int C_PTR bytesCopied );
C_RET cryptPopData( C_IN CRYPT_HANDLE envelope, C_OUT void C_PTR buffer,
				    C_IN int length, C_OUT int C_PTR bytesCopied );

/****************************************************************************
*																			*
*								Device Functions							*
*																			*
****************************************************************************/

/* Open and close a device */

C_RET cryptDeviceOpen( C_OUT CRYPT_DEVICE C_PTR device,
					   C_IN CRYPT_DEVICE_TYPE deviceType,
					   C_IN char C_PTR name );
C_RET cryptDeviceClose( C_IN CRYPT_DEVICE device );

/* Query a devices capabilities */

C_RET cryptDeviceQueryCapability( C_IN CRYPT_DEVICE device,
								  C_IN CRYPT_ALGO cryptAlgo,
								  C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo );

/* Create an encryption context via the device */

C_RET cryptDeviceCreateContext( C_IN CRYPT_DEVICE device,
							    C_OUT CRYPT_CONTEXT C_PTR cryptContext,
							    C_IN CRYPT_ALGO cryptAlgo );

/* Peform a control function on the device.  This is a kludge extension to 
   cryptSetAttributeString() which will be replaced by that function once
   a clean means of passing two sets of parameters is found */

C_RET cryptDeviceControlEx( C_IN CRYPT_DEVICE device,
						    C_IN CRYPT_ATTRIBUTE_TYPE controlType,
						    C_IN void C_PTR data1, C_IN int data1Length,
						    C_IN void C_PTR data2, C_IN int data2Length );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CRYPTLIB_DEFINED */

unit cryptlib;

interface

{****************************************************************************
*                                                                           *
*                        cryptlib External API Interface                    *
*                       Copyright Peter Gutmann 1997-2000                   *
*                                                                           *
*               adapted for Delphi Version 5 (32 bit) by W. Gothier         *
****************************************************************************}

{------------------------------------------------------------------------------

 This file has been created automatically by a perl script ( with very little
 postprocessing manually) from the file:

 "cryptlib.h" dated Thu Apr 20 21:30:40 2000, filesize = 63881.

 Please check twice that the file matches the version of cryptlib.h
 in your cryptlib source! If the filesize or file creation date do not match,
 then please do not complain about problems.

 Published by W. Gothier, mailto: hwg@gmx.de if you find errors in this file.

-------------------------------------------------------------------------------}

{$A+}  {Set Alignment on}
{$F+}  {Force function calls to FAR}
{$Z+}  {Force all enumeration values to Integer size}

{  Alongside the externally visible types, cryptlib also has various internal
   types which are extended forms of the external types which are invisible
   to the user (eg SignedPublicKeyAndChallenge == certRequest).  These can
   only be used internally and are blocked by the security kernel, so they
   can never be accessed from outside cryptlib (in fact for good measure
   they're blocked before they even get to the kernel by preliminary range
   checks in the API wrapper functions).  The only reason they're defined
   here is because it's not possible to extend an enum outside the point
   where it's originally defined  }

{****************************************************************************
*                                                                           *
*                           Algorithm and Object Types                      *
*                                                                           *
****************************************************************************}

{  Algorithm and mode types  }

type
  CRYPT_ALGO = Integer;
const
  { Algorithms }
  { No encryption }
  CRYPT_ALGO_NONE                                  = 0; { No encryption }

  { Conventional encryption }
  CRYPT_ALGO_DES                                   = 1; { DES }
  CRYPT_ALGO_3DES                                  = 2; { Triple DES }
  CRYPT_ALGO_IDEA                                  = 3; { IDEA }
  CRYPT_ALGO_CAST                                  = 4; { CAST-128 }
  CRYPT_ALGO_RC2                                   = 5; { RC2 }
  CRYPT_ALGO_RC4                                   = 6; { RC4 }
  CRYPT_ALGO_RC5                                   = 7; { RC5 }
  CRYPT_ALGO_SAFER                                 = 8; { SAFER/SAFER-SK - deprecated }
  CRYPT_ALGO_BLOWFISH                              = 9; { Blowfish }
  CRYPT_ALGO_SKIPJACK                              = 10; { Skipjack }
  CRYPT_ALGO_GOST                                  = 11; { GOST 28147 (not implemented yet) }

  { Public-key encryption }
  CRYPT_ALGO_DH                                    = 100; { Diffie-Hellman }
  CRYPT_ALGO_RSA                                   = 101; { RSA }
  CRYPT_ALGO_DSA                                   = 102; { DSA }
  CRYPT_ALGO_ELGAMAL                               = 103; { ElGamal }
  CRYPT_ALGO_KEA                                   = 104; { KEA }

  { Hash algorithms }
  CRYPT_ALGO_MD2                                   = 200; { MD2 }
  CRYPT_ALGO_MD4                                   = 201; { MD4 }
  CRYPT_ALGO_MD5                                   = 202; { MD5 }
  CRYPT_ALGO_SHA                                   = 203; { SHA/SHA1 }
  CRYPT_ALGO_RIPEMD160                             = 204; { RIPE-MD 160 }
  CRYPT_ALGO_MDC2                                  = 205; { MDC-2 }

  { MAC's }
  CRYPT_ALGO_HMAC_MD5                              = 300; { HMAC-MD5 }
  CRYPT_ALGO_HMAC_SHA                              = 301; { HMAC-SHA }
  CRYPT_ALGO_HMAC_RIPEMD160                        = 302; { HMAC-RIPEMD-160 }

  CRYPT_ALGO_LAST                                  = 303; { Last possible crypt algo value }

  { Vendors may want to use their own algorithms which aren't part of the
  general cryptlib suite.  The following values are for vendor-defined
  algorithms, and can be used just like the named algorithm types (it's
  up to the vendor to keep track of what _VENDOR1 actually corresponds
  to) }
  CRYPT_ALGO_VENDOR1                               = 10000;
  CRYPT_ALGO_VENDOR2                               = 10001;
  CRYPT_ALGO_VENDOR3                               = 10002;

  { In order that we can scan through a range of algorithms with
  cryptQueryCapability(), we define the following boundary points for
  each algorithm class }
  CRYPT_ALGO_FIRST_CONVENTIONAL                    = 1; {  = CRYPT_ALGO_DES  }
  CRYPT_ALGO_LAST_CONVENTIONAL                     = 99;
  CRYPT_ALGO_FIRST_PKC                             = 100; {  = CRYPT_ALGO_DH  }
  CRYPT_ALGO_LAST_PKC                              = 199;
  CRYPT_ALGO_FIRST_HASH                            = 200; {  = CRYPT_ALGO_MD2  }
  CRYPT_ALGO_LAST_HASH                             = 299;
  CRYPT_ALGO_FIRST_MAC                             = 300; {  = CRYPT_ALGO_HMAC_MD5  }
  CRYPT_ALGO_LAST_MAC                              = 399; { End of mac algo.range }

type
  CRYPT_MODE = Integer;
const
  { Modes }
  { No encryption }
  CRYPT_MODE_NONE                                  = 0; { No encryption (hashes and MAC's) }

  { Stream cipher modes }
  CRYPT_MODE_STREAM                                = 1; { Stream cipher }

  { Block cipher modes }
  CRYPT_MODE_ECB                                   = 2; { ECB }
  CRYPT_MODE_CBC                                   = 3; { CBC }
  CRYPT_MODE_CFB                                   = 4; { CFB }
  CRYPT_MODE_OFB                                   = 5; { OFB }

  { Public-key cipher modes }
  CRYPT_MODE_PKC                                   = 100; { PKC }

  CRYPT_MODE_LAST                                  = 101; { Last possible crypt mode value }

  { In order that we can scan through a range of modes with
  cryptQueryCapability(), we define the following boundary points for
  the conventional encryption modes }
  CRYPT_MODE_FIRST_CONVENTIONAL                    = 1; {  = CRYPT_MODE_STREAM  }
  CRYPT_MODE_LAST_CONVENTIONAL                     = 99;

  {  Object subtypes  }

type
  CRYPT_KEYSET_TYPE = (                              {  Keyset types  }
    CRYPT_KEYSET_NONE,                               {  No keyset type  }
    CRYPT_KEYSET_FILE,                               {  Generic flat file keyset (PGP, X.509)  }
    CRYPT_KEYSET_HTTP,                               {  Web page containing cert/CRL  }
    CRYPT_KEYSET_LDAP,                               {  LDAP directory service  }
    CRYPT_KEYSET_SMARTCARD,                          {  Smart card key carrier  }
    CRYPT_KEYSET_ODBC,                               {  Generic ODBC interface  }
    CRYPT_KEYSET_MSQL,                               {  mSQL RDBMS  }
    CRYPT_KEYSET_MYSQL,                              {  MySQL RDBMS  }
    CRYPT_KEYSET_ORACLE,                             {  Oracle RDBMS  }
    CRYPT_KEYSET_POSTGRES,                           {  Postgres RDBMS  }
    CRYPT_KEYSET_LAST                                {  Last possible keyset type  }

    );

  CRYPT_DEVICE_TYPE = (                              {  Crypto device types  }
    CRYPT_DEVICE_NONE,                               {  No crypto device  }
    CRYPT_DEVICE_FORTEZZA,                           {  Fortezza card  }
    CRYPT_DEVICE_PKCS11,                             {  PKCS #11 crypto token  }
    CRYPT_DEVICE_LAST                                {  Last possible crypto device type  }

    );

  CRYPT_CERTTYPE_TYPE = (                            {  Certificate object types  }
    CRYPT_CERTTYPE_NONE,                             {  No certificate type  }
    CRYPT_CERTTYPE_CERTIFICATE,                      {  Certificate  }
    CRYPT_CERTTYPE_ATTRIBUTE_CERT,                   {  Attribute certificate  }
    CRYPT_CERTTYPE_CERTCHAIN,                        {  PKCS #7 certificate chain  }
    CRYPT_CERTTYPE_CERTREQUEST,                      {  PKCS #10 certification request  }
    CRYPT_CERTTYPE_CRL,                              {  CRL  }
    CRYPT_CERTTYPE_OCSP_REQUEST,                     {  OCSP request  }
    CRYPT_CERTTYPE_OCSP_RESPONSE,                    {  OCSP response  }
    CRYPT_CERTTYPE_CMS_ATTRIBUTES,                   {  CMS attributes  }
    CRYPT_CERTTYPE_LAST                              {  Last possible cert.type  }

    );

  {****************************************************************************
  *                                                                         *
  *                             Attribute Types                             *
  *                                                                         *
  ****************************************************************************}

  {  Attribute types.  These are arranged in the following order:

   PROPERTY - Object property
   ATTRIBUTE    - Generic attributes
   OPTION       - Global or object-specific config.option
   CTXINFO      - Context-specific attribute
   CERTINFO - Certificate-specific attribute
   KEYSETINFO   - Keyset-specific attribute
   DEVINFO      - Device-specific attribute
   ENVINFO      - Envelope-specific attribute
   SESSINFO - Session-specific attribute  }

  CRYPT_ATTRIBUTE_TYPE = Integer;
const

  CRYPT_ATTRIBUTE_NONE                             = 0; { Non-value }

  { Used internally }
  CRYPT_PROPERTY_FIRST                             = 1;

  {*******************}
  { Object attributes }
  {*******************}

  { Object properties }
  CRYPT_PROPERTY_HIGHSECURITY                      = 2; { Owned+non-forwardable+locked }
  CRYPT_PROPERTY_OWNER                             = 3; { Object owner }
  CRYPT_PROPERTY_FORWARDABLE                       = 4; { No.of times object can be forwarded }
  CRYPT_PROPERTY_LOCKED                            = 5; { Whether properties can be chged/read }
  CRYPT_PROPERTY_USAGECOUNT                        = 6; { Usage count before object expires }
  CRYPT_PROPERTY_ENCRYPTONLY                       = 7; { Whether context can be used only }
  CRYPT_PROPERTY_DECRYPTONLY                       = 8; {   for encryption or decryption }
  CRYPT_PROPERTY_NONEXPORTABLE                     = 9; { Whether key is nonexp.from context }

  { Used internally }
  CRYPT_PROPERTY_LAST                              = 10;
  CRYPT_GENERIC_FIRST                              = 11;

  { Extended error information }
  CRYPT_ATTRIBUTE_ERRORTYPE                        = 12; { Type of last error }
  CRYPT_ATTRIBUTE_ERRORLOCUS                       = 13; { Locus of last error }
  CRYPT_ATTRIBUTE_INT_ERRORCODE                    = 14; { Low-level software-specific }
  CRYPT_ATTRIBUTE_INT_ERRORMESSAGE                 = 15; {   error code and message }

  { Generic information }
  CRYPT_ATTRIBUTE_BUFFERSIZE                       = 16; { Internal data buffer size }

  { User internally }
  CRYPT_GENERIC_LAST                               = 17;
  CRYPT_OPTION_FIRST                               = 100;

  {**************************}
  { Configuration attributes }
  {**************************}

  { cryptlib information (read-only) }
  CRYPT_OPTION_INFO_DESCRIPTION                    = 101; { Text description }
  CRYPT_OPTION_INFO_COPYRIGHT                      = 102; { Copyright notice }
  CRYPT_OPTION_INFO_MAJORVERSION                   = 103; { Major release version }
  CRYPT_OPTION_INFO_MINORVERSION                   = 104; { Minor release version }
  CRYPT_OPTION_INFO_STEPPING                       = 105; { Release stepping }

  { Encryption options }
  CRYPT_OPTION_ENCR_ALGO                           = 106; { Encryption algorithm }
  CRYPT_OPTION_ENCR_MODE                           = 107; { Encryption mode }
  CRYPT_OPTION_ENCR_HASH                           = 108; { Hash algorithm }

  { PKC options }
  CRYPT_OPTION_PKC_ALGO                            = 109; { Public-key encryption algorithm }
  CRYPT_OPTION_PKC_KEYSIZE                         = 110; { Public-key encryption key size }

  { Signature options }
  CRYPT_OPTION_SIG_ALGO                            = 111; { Signature algorithm }
  CRYPT_OPTION_SIG_KEYSIZE                         = 112; { Signature keysize }

  { Keying options }
  CRYPT_OPTION_KEYING_ALGO                         = 113; { Key processing algorithm }
  CRYPT_OPTION_KEYING_ITERATIONS                   = 114; { Key processing iterations }

  { Certificate options }
  CRYPT_OPTION_CERT_CREATEV3CERT                   = 115; { Whether to create X.509v3 certs }
  CRYPT_OPTION_CERT_PKCS10ALT                      = 116; { Use alternative PKCS #10 encoding }
  CRYPT_OPTION_CERT_CHECKENCODING                  = 117; { Check for valid ASN.1 encoding }
  CRYPT_OPTION_CERT_FIXSTRINGS                     = 118; { Whether to fix encoding of strings }
  CRYPT_OPTION_CERT_FIXEMAILADDRESS                = 119; { Whether to fix encoding of email addr.}
  CRYPT_OPTION_CERT_ISSUERNAMEBLOB                 = 120; { Whether to treat iName as a blob }
  CRYPT_OPTION_CERT_KEYIDBLOB                      = 121; { Whether to treat keyID as a blob }
  CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES     = 122; { Whether to sign unrecog.attrs }
  CRYPT_OPTION_CERT_TRUSTCHAINROOT                 = 123; { Whether to trust cert chain root }
  CRYPT_OPTION_CERT_VALIDITY                       = 124; { Certificate validity period }
  CRYPT_OPTION_CERT_UPDATEINTERVAL                 = 125; { CRL update interval }
  CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING         = 126;
  CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING         = 127; { Enforce validity nesting on R/W }
  CRYPT_OPTION_CERT_ENCODE_CRITICAL                = 128;
  CRYPT_OPTION_CERT_DECODE_CRITICAL                = 129; { Enforce critical flag in extensions }

  { CMS/SMIME options }
  CRYPT_OPTION_CMS_DEFAULTATTRIBUTES               = 130; { Add default CMS attributes }
  CRYPT_OPTION_SMIME_DEFAULTATTRIBUTES             = 130; {  = CRYPT_OPTION_CMS_DEFAULTATTRIBUTES  }

  { HTTP keyset access options }
  CRYPT_OPTION_KEYS_HTTP_PROXY                     = 131; { URL of web proxy }
  CRYPT_OPTION_KEYS_HTTP_TIMEOUT                   = 132; { Timeout for read }

  { LDAP keyset options }
  CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS               = 133; { Object class }
  CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE                = 134; { Object type to fetch }
  CRYPT_OPTION_KEYS_LDAP_CACERTNAME                = 135; { CA certificate attribute name }
  CRYPT_OPTION_KEYS_LDAP_CERTNAME                  = 136; { Certificate attribute name }
  CRYPT_OPTION_KEYS_LDAP_CRLNAME                   = 137; { CRL attribute name }
  CRYPT_OPTION_KEYS_LDAP_EMAILNAME                 = 138; { Email attribute name }

  { Crypto device options }
  CRYPT_OPTION_DEVICE_PKCS11_DVR01                 = 139; { Name of first PKCS #11 driver }
  CRYPT_OPTION_DEVICE_PKCS11_DVR02                 = 140; { Name of second PKCS #11 driver }
  CRYPT_OPTION_DEVICE_PKCS11_DVR03                 = 141; { Name of third PKCS #11 driver }
  CRYPT_OPTION_DEVICE_PKCS11_DVR04                 = 142; { Name of fourth PKCS #11 driver }
  CRYPT_OPTION_DEVICE_PKCS11_DVR05                 = 143; { Name of fifth PKCS #11 driver }
  CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY          = 144; { Use only hardware mechanisms }
  CRYPT_OPTION_DEVICE_SERIALRNG                    = 145; { Serial-port-based RNG name }
  CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS             = 146; { Serial RNG parameters }

  { Session options }
  CRYPT_OPTION_SESSION_TIMEOUT                     = 147; { Timeout for network accesses }

  { Miscellaneous options }
  CRYPT_OPTION_MISC_FORCELOCK                      = 148; { Whether to force memory locking }
  CRYPT_OPTION_MISC_ASYNCINIT                      = 149; { Whether to init cryptlib async'ly }

  { Config option status }
  CRYPT_OPTION_CONFIGCHANGED                       = 150; { Whether in-mem.opts match on-disk ones }

  { Used internally }
  CRYPT_OPTION_LAST                                = 151;
  CRYPT_CTXINFO_FIRST                              = 1000;

  {********************}
  { Context attributes }
  {********************}

  { Algorithm and mode information }
  CRYPT_CTXINFO_ALGO                               = 1001; { Algorithm }
  CRYPT_CTXINFO_MODE                               = 1002; { Mode }
  CRYPT_CTXINFO_NAME_ALGO                          = 1003; { Algorithm name }
  CRYPT_CTXINFO_NAME_MODE                          = 1004; { Mode name }
  CRYPT_CTXINFO_KEYSIZE                            = 1005; { Key size in bytes }
  CRYPT_CTXINFO_BLOCKSIZE                          = 1006; { Block size }
  CRYPT_CTXINFO_IVSIZE                             = 1007; { IV size }
  CRYPT_CTXINFO_KEYING_ALGO                        = 1008; { Key processing algorithm }
  CRYPT_CTXINFO_KEYING_ITERATIONS                  = 1009; { Key processing iterations }
  CRYPT_CTXINFO_KEYING_SALT                        = 1010; { Key processing salt }
  CRYPT_CTXINFO_KEYING_VALUE                       = 1011; { Value used to derive key }

  { State information }
  CRYPT_CTXINFO_KEY                                = 1012; { Key }
  CRYPT_CTXINFO_KEY_COMPONENTS                     = 1013; { Public-key components }
  CRYPT_CTXINFO_IV                                 = 1014; { IV }
  CRYPT_CTXINFO_HASHVALUE                          = 1015; { Hash value }

  { Misc.information }
  CRYPT_CTXINFO_LABEL                              = 1016; { Label for private key }

  { Used internally }
  CRYPT_CTXINFO_LAST                               = 1017;
  CRYPT_CERTINFO_FIRST                             = 2000;

  {************************}
  { Certificate attributes }
  {************************}

  { Pseudo-information on a cert object or meta-information which is used
  to control the way a cert object is processed }
  CRYPT_CERTINFO_SELFSIGNED                        = 2001; { Cert is self-signed }
  CRYPT_CERTINFO_IMMUTABLE                         = 2002; { Cert is signed and immutable }
  CRYPT_CERTINFO_CERTTYPE                          = 2003; { Certificate object type }
  CRYPT_CERTINFO_FINGERPRINT                       = 2004; { Certificate fingerprints }
  CRYPT_CERTINFO_FINGERPRINT_MD5                   = 2004; {  = CRYPT_CERTINFO_FINGERPRINT  }
  CRYPT_CERTINFO_FINGERPRINT_SHA                   = 2005;
  CRYPT_CERTINFO_CURRENT_CERTIFICATE               = 2006; { Certificate cursor management }
  CRYPT_CERTINFO_CURRENT_EXTENSION                 = 2007;
  CRYPT_CERTINFO_CURRENT_FIELD                     = 2008;
  CRYPT_CERTINFO_CURRENT_COMPONENT                 = 2009; { Extension cursor management }
  CRYPT_CERTINFO_TRUSTED_USAGE                     = 2010; { Usage which cert is trusted for }
  CRYPT_CERTINFO_TRUSTED_IMPLICIT                  = 2011; { Whether cert is implicitly trusted }

  { General certificate/CRL/cert request information }
  CRYPT_CERTINFO_SERIALNUMBER                      = 2012; { Serial number (read-only) }
  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO              = 2013; { Public key }
  CRYPT_CERTINFO_USERCERTIFICATE                   = 2014; { User certificate }
  CRYPT_CERTINFO_CERTIFICATE                       = 2014; {  = CRYPT_CERTINFO_USERCERTIFICATE  }
  CRYPT_CERTINFO_ISSUERNAME                        = 2015; { Issuer DN (read-only) }
  CRYPT_CERTINFO_VALIDFROM                         = 2016; { Cert valid from time }
  CRYPT_CERTINFO_VALIDTO                           = 2017; { Cert valid to time }
  CRYPT_CERTINFO_SUBJECTNAME                       = 2018; { Subject DN }
  CRYPT_CERTINFO_ISSUERUNIQUEID                    = 2019; { Issuer unique ID (read-only) }
  CRYPT_CERTINFO_SUBJECTUNIQUEID                   = 2020; { Subject unique ID (read-only) }
  CRYPT_CERTINFO_CERTREQUEST                       = 2021; { Cert.request (DN + public key) }
  CRYPT_CERTINFO_THISUPDATE                        = 2022; { CRL current update time }
  CRYPT_CERTINFO_NEXTUPDATE                        = 2023; { CRL next update time }
  CRYPT_CERTINFO_REVOCATIONDATE                    = 2024; { CRL cert revocation time }

  { X.520 Distinguished Name components.  This is a composite field, the
  DN to be manipulated is selected through the addition of a
  pseudocomponent, and then one of the following is used to access the
  DN components directly }
  CRYPT_CERTINFO_COUNTRYNAME                       = 2100; { countryName }
  CRYPT_CERTINFO_STATEORPROVINCENAME               = 2101; { stateOrProvinceName }
  CRYPT_CERTINFO_LOCALITYNAME                      = 2102; { localityName }
  CRYPT_CERTINFO_ORGANIZATIONNAME                  = 2103; { organizationName }
  CRYPT_CERTINFO_ORGANISATIONNAME                  = 2103; {  = CRYPT_CERTINFO_ORGANIZATIONNAME  }
  CRYPT_CERTINFO_ORGANIZATIONALUNITNAME            = 2104; { organizationalUnitName }
  CRYPT_CERTINFO_ORGANISATIONALUNITNAME            = 2104; {  = CRYPT_CERTINFO_ORGANIZATIONALUNITNAME  }
  CRYPT_CERTINFO_COMMONNAME                        = 2105; { commonName }

  { X.509 General Name components.  These are handled in the same way as
  the DN composite field, with the current GeneralName being selected by
  a pseudo-component after which the individual components can be
  modified through one of the following }
  CRYPT_CERTINFO_OTHERNAME_TYPEID                  = 2106; { otherName.typeID }
  CRYPT_CERTINFO_OTHERNAME_VALUE                   = 2107; { otherName.value }
  CRYPT_CERTINFO_RFC822NAME                        = 2108; { rfc822Name }
  CRYPT_CERTINFO_EMAIL                             = 2108; {  = CRYPT_CERTINFO_RFC822NAME  }
  CRYPT_CERTINFO_DNSNAME                           = 2109; { dNSName }
  CRYPT_CERTINFO_DIRECTORYNAME                     = 2110; { directoryName }
  CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER         = 2111; { ediPartyName.nameAssigner }
  CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME            = 2112; { ediPartyName.partyName }
  CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER         = 2113; { uniformResourceIdentifier }
  CRYPT_CERTINFO_IPADDRESS                         = 2114; { iPAddress }
  CRYPT_CERTINFO_REGISTEREDID                      = 2115; { registeredID }

  { X.509v3 certificate extensions.  Although it would be nicer to use
  names which match the extensions more closely (eg
  CRYPT_CERTINFO_BASICCONSTRAINTS_PATHLENCONSTRAINT), these exceed the
  32-character ANSI minimum length for unique names, and get really
  hairy once you get into the weird policy constraints extensions whose
  names wrap around the screen about three times.

  The following values are defined in OID order, this isn't absolutely
  necessary but saves an extra layer of processing when encoding them }

  { 1 3 6 1 5 5 7 1 1 authorityInfoAccess }
  CRYPT_CERTINFO_AUTHORITYINFOACCESS               = 2200;
  CRYPT_CERTINFO_AUTHORITYINFO_OCSP                = 2201; { accessDescription.accessLocation }
  CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS           = 2202; { accessDescription.accessLocation }

  { 1 3 36 8 3 1 }
  CRYPT_CERTINFO_SIGG_DATEOFCERTGEN                = 2203;

  { 1 3 36 8 3 2 }
  CRYPT_CERTINFO_SIGG_PROCURATION                  = 2204;
  CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY              = 2205; { country }
  CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION   = 2206; { typeOfSubstitution }
  CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR           = 2207; { signingFor.thirdPerson }

  { 1 3 36 8 3 4 }
  CRYPT_CERTINFO_SIGG_MONETARYLIMIT                = 2208;
  CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY            = 2209; { currency }
  CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT              = 2210; { amount }
  CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT            = 2211; { exponent }

  { 1 3 36 8 3 8 }
  CRYPT_CERTINFO_SIGG_RESTRICTION                  = 2212;

  { 1 3 101 1 4 1 strongExtranet }
  CRYPT_CERTINFO_STRONGEXTRANET                    = 2213;
  CRYPT_CERTINFO_STRONGEXTRANET_ZONE               = 2214; { sxNetIDList.sxNetID.zone }
  CRYPT_CERTINFO_STRONGEXTRANET_ID                 = 2215; { sxNetIDList.sxNetID.id }

  { 2 5 29 9 subjectDirectoryAttributes }
  CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES        = 2216;
  CRYPT_CERTINFO_SUBJECTDIR_TYPE                   = 2217; { attribute.type }
  CRYPT_CERTINFO_SUBJECTDIR_VALUES                 = 2218; { attribute.values }

  { 2 5 29 14 subjectKeyIdentifier }
  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER              = 2219;

  { 2 5 29 15 keyUsage }
  CRYPT_CERTINFO_KEYUSAGE                          = 2220;

  { 2 5 29 16 privateKeyUsagePeriod }
  CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD             = 2221;
  CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE              = 2222; { notBefore }
  CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER               = 2223; { notAfter }

  { 2 5 29 17 subjectAltName }
  CRYPT_CERTINFO_SUBJECTALTNAME                    = 2224;

  { 2 5 29 18 issuerAltName }
  CRYPT_CERTINFO_ISSUERALTNAME                     = 2225;

  { 2 5 29 19 basicConstraints }
  CRYPT_CERTINFO_BASICCONSTRAINTS                  = 2226;
  CRYPT_CERTINFO_CA                                = 2227; { cA }
  CRYPT_CERTINFO_AUTHORITY                         = 2227; {  = CRYPT_CERTINFO_CA  }
  CRYPT_CERTINFO_PATHLENCONSTRAINT                 = 2228; { pathLenConstraint }

  { 2 5 29 20 cRLNumber }
  CRYPT_CERTINFO_CRLNUMBER                         = 2229;

  { 2 5 29 21 cRLReason }
  CRYPT_CERTINFO_CRLREASON                         = 2230;

  { 2 5 29 23 holdInstructionCode }
  CRYPT_CERTINFO_HOLDINSTRUCTIONCODE               = 2231;

  { 2 5 29 24 invalidityDate }
  CRYPT_CERTINFO_INVALIDITYDATE                    = 2232;

  { 2 5 29 27 deltaCRLIndicator }
  CRYPT_CERTINFO_DELTACRLINDICATOR                 = 2233;

  { 2 5 29 28 issuingDistributionPoint }
  CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT          = 2234;
  CRYPT_CERTINFO_ISSUINGDIST_FULLNAME              = 2235; { distributionPointName.fullName }
  CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY         = 2236; { onlyContainsUserCerts }
  CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY           = 2237; { onlyContainsCACerts }
  CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY       = 2238; { onlySomeReasons }
  CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL           = 2239; { indirectCRL }

  { 2 5 29 29 certificateIssuer }
  CRYPT_CERTINFO_CERTIFICATEISSUER                 = 2240;

  { 2 5 29 30 nameConstraints }
  CRYPT_CERTINFO_NAMECONSTRAINTS                   = 2241;
  CRYPT_CERTINFO_PERMITTEDSUBTREES                 = 2242; { permittedSubtrees }
  CRYPT_CERTINFO_EXCLUDEDSUBTREES                  = 2243; { excludedSubtrees }

  { 2 5 29 31 cRLDistributionPoint }
  CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT              = 2244;
  CRYPT_CERTINFO_CRLDIST_FULLNAME                  = 2245; { distributionPointName.fullName }
  CRYPT_CERTINFO_CRLDIST_REASONS                   = 2246; { reasons }
  CRYPT_CERTINFO_CRLDIST_CRLISSUER                 = 2247; { cRLIssuer }

  { 2 5 29 32 certificatePolicies }
  CRYPT_CERTINFO_CERTIFICATEPOLICIES               = 2248;
  CRYPT_CERTINFO_CERTPOLICYID                      = 2249; { policyInformation.policyIdentifier }
  CRYPT_CERTINFO_CERTPOLICY_CPSURI                 = 2250;
  { policyInformation.policyQualifiers.qualifier.cPSuri }
  CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION           = 2251;
  { policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization }
  CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS          = 2252;
  { policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers }
  CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT           = 2253;
  { policyInformation.policyQualifiers.qualifier.userNotice.explicitText }

  { 2 5 29 33 policyMappings }
  CRYPT_CERTINFO_POLICYMAPPINGS                    = 2254;
  CRYPT_CERTINFO_ISSUERDOMAINPOLICY                = 2255; { policyMappings.issuerDomainPolicy }
  CRYPT_CERTINFO_SUBJECTDOMAINPOLICY               = 2256; { policyMappings.subjectDomainPolicy }

  { 2 5 29 35 authorityKeyIdentifier }
  CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER            = 2257;
  CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER           = 2258; { keyIdentifier }
  CRYPT_CERTINFO_AUTHORITY_CERTISSUER              = 2259; { authorityCertIssuer }
  CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER        = 2260; { authorityCertSerialNumber }

  { 2 5 29 36 policyConstraints }
  CRYPT_CERTINFO_POLICYCONSTRAINTS                 = 2261;
  CRYPT_CERTINFO_REQUIREEXPLICITPOLICY             = 2262; { policyConstraints.requireExplicitPolicy }
  CRYPT_CERTINFO_INHIBITPOLICYMAPPING              = 2263; { policyConstraints.inhibitPolicyMapping }

  { 2 5 29 37 extKeyUsage }
  CRYPT_CERTINFO_EXTKEYUSAGE                       = 2264;
  CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING   = 2265; { individualCodeSigning }
  CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING   = 2266; { commercialCodeSigning }
  CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING    = 2267; { certTrustListSigning }
  CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING        = 2268; { timeStampSigning }
  CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO       = 2269; { serverGatedCrypto }
  CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM     = 2270; { encrypedFileSystem }
  CRYPT_CERTINFO_EXTKEY_SERVERAUTH                 = 2271; { serverAuth }
  CRYPT_CERTINFO_EXTKEY_CLIENTAUTH                 = 2272; { clientAuth }
  CRYPT_CERTINFO_EXTKEY_CODESIGNING                = 2273; { codeSigning }
  CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION            = 2274; { emailProtection }
  CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM             = 2275; { ipsecEndSystem }
  CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL                = 2276; { ipsecTunnel }
  CRYPT_CERTINFO_EXTKEY_IPSECUSER                  = 2277; { ipsecUser }
  CRYPT_CERTINFO_EXTKEY_TIMESTAMPING               = 2278; { timeStamping }
  CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE           = 2279; { directoryService }
  CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO       = 2280; { serverGatedCrypto }
  CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA    = 2281; { serverGatedCrypto CA }

  { 2 16 840 1 113730 1 x Netscape extensions }
  CRYPT_CERTINFO_NS_CERTTYPE                       = 2282; { netscape-cert-type }
  CRYPT_CERTINFO_NS_BASEURL                        = 2283; { netscape-base-url }
  CRYPT_CERTINFO_NS_REVOCATIONURL                  = 2284; { netscape-revocation-url }
  CRYPT_CERTINFO_NS_CAREVOCATIONURL                = 2285; { netscape-ca-revocation-url }
  CRYPT_CERTINFO_NS_CERTRENEWALURL                 = 2286; { netscape-cert-renewal-url }
  CRYPT_CERTINFO_NS_CAPOLICYURL                    = 2287; { netscape-ca-policy-url }
  CRYPT_CERTINFO_NS_SSLSERVERNAME                  = 2288; { netscape-ssl-server-name }
  CRYPT_CERTINFO_NS_COMMENT                        = 2289; { netscape-comment }

  { 2 23 42 7 0 SET hashedRootKey }
  CRYPT_CERTINFO_SET_HASHEDROOTKEY                 = 2290;
  CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT             = 2291; { rootKeyThumbPrint }

  { 2 23 42 7 1 SET certificateType }
  CRYPT_CERTINFO_SET_CERTIFICATETYPE               = 2292;

  { 2 23 42 7 2 SET merchantData }
  CRYPT_CERTINFO_SET_MERCHANTDATA                  = 2293;
  CRYPT_CERTINFO_SET_MERID                         = 2294; { merID }
  CRYPT_CERTINFO_SET_MERACQUIRERBIN                = 2295; { merAcquirerBIN }
  CRYPT_CERTINFO_SET_MERCHANTLANGUAGE              = 2296; { merNames.language }
  CRYPT_CERTINFO_SET_MERCHANTNAME                  = 2297; { merNames.name }
  CRYPT_CERTINFO_SET_MERCHANTCITY                  = 2298; { merNames.city }
  CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE         = 2299; { merNames.stateProvince }
  CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE            = 2300; { merNames.postalCode }
  CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME           = 2301; { merNames.countryName }
  CRYPT_CERTINFO_SET_MERCOUNTRY                    = 2302; { merCountry }
  CRYPT_CERTINFO_SET_MERAUTHFLAG                   = 2303; { merAuthFlag }

  { 2 23 42 7 3 SET certCardRequired }
  CRYPT_CERTINFO_SET_CERTCARDREQUIRED              = 2304;

  { 2 23 42 7 4 SET tunneling }
  CRYPT_CERTINFO_SET_TUNNELING                     = 2305;
  CRYPT_CERTINFO_SET_TUNNELINGFLAG                 = 2306; { tunneling }
  CRYPT_CERTINFO_SET_TUNNELINGALGID                = 2307; { tunnelingAlgID }

  { S/MIME attributes }

  { 1 2 840 113549 1 9 3 contentType }
  CRYPT_CERTINFO_CMS_CONTENTTYPE                   = 2500;

  { 1 2 840 113549 1 9 4 messageDigest }
  CRYPT_CERTINFO_CMS_MESSAGEDIGEST                 = 2501;

  { 1 2 840 113549 1 9 5 signingTime }
  CRYPT_CERTINFO_CMS_SIGNINGTIME                   = 2502;

  { 1 2 840 113549 1 9 6 counterSignature }
  CRYPT_CERTINFO_CMS_COUNTERSIGNATURE              = 2503; { counterSignature }

  { 1 2 840 113549 1 9 15 sMIMECapabilities }
  CRYPT_CERTINFO_CMS_SMIMECAPABILITIES             = 2504;
  CRYPT_CERTINFO_CMS_SMIMECAP_3DES                 = 2505; { 3DES encryption }
  CRYPT_CERTINFO_CMS_SMIMECAP_CAST128              = 2506; { CAST-128 encryption }
  CRYPT_CERTINFO_CMS_SMIMECAP_IDEA                 = 2507; { IDEA encryption }
  CRYPT_CERTINFO_CMS_SMIMECAP_RC2                  = 2508; { RC2 encryption (w.128 key) }
  CRYPT_CERTINFO_CMS_SMIMECAP_RC5                  = 2509; { RC5 encryption (w.128 key) }
  CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK             = 2510; { Skipjack encryption }
  CRYPT_CERTINFO_CMS_SMIMECAP_DES                  = 2511; { DES encryption }
  CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA     = 2512; { preferSignedData }
  CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY     = 2513; { canNotDecryptAny }

  { 1 2 840 113549 1 9 16 2 1 receiptRequest }
  CRYPT_CERTINFO_CMS_RECEIPTREQUEST                = 2514;
  CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER     = 2515; { contentIdentifier }
  CRYPT_CERTINFO_CMS_RECEIPT_FROM                  = 2516; { receiptsFrom }
  CRYPT_CERTINFO_CMS_RECEIPT_TO                    = 2517; { receiptsTo }

  { 1 2 840 113549 1 9 16 2 2 essSecurityLabel }
  CRYPT_CERTINFO_CMS_SECURITYLABEL                 = 2518;
  CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION       = 2519; { securityClassification }
  CRYPT_CERTINFO_CMS_SECLABEL_POLICY               = 2520; { securityPolicyIdentifier }
  CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK          = 2521; { privacyMark }
  CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE              = 2522; { securityCategories.securityCategory.type }
  CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE             = 2523; { securityCategories.securityCategory.value }

  { 1 2 840 113549 1 9 16 2 3 mlExpansionHistory }
  CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY            = 2524;
  CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER        = 2525; { mlData.mailListIdentifier.issuerAndSerialNumber }
  CRYPT_CERTINFO_CMS_MLEXP_TIME                    = 2526; { mlData.expansionTime }
  CRYPT_CERTINFO_CMS_MLEXP_NONE                    = 2527; { mlData.mlReceiptPolicy.none }
  CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF               = 2528; { mlData.mlReceiptPolicy.insteadOf.generalNames.generalName }
  CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO            = 2529;  { mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName }

  { 1 2 840 113549 1 9 16 2 4 contentHints }
  CRYPT_CERTINFO_CMS_CONTENTHINTS                  = 2530;
  CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION       = 2531; { contentDescription }
  CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE              = 2532; { contentType }

  { 1 2 840 113549 1 9 16 2 8 macValue }
  CRYPT_CERTINFO_CMS_MACVALUE                      = 2533; { macValue }

  { 1 2 840 113549 1 9 16 2 9 equivalentLabels }
  CRYPT_CERTINFO_CMS_EQUIVALENTLABEL               = 2534;
  CRYPT_CERTINFO_CMS_EQVLABEL_POLICY               = 2535; { securityPolicyIdentifier }
  CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION       = 2536; { securityClassification }
  CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK          = 2537; { privacyMark }
  CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE              = 2538; { securityCategories.securityCategory.type }
  CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE             = 2539; { securityCategories.securityCategory.value }

  { 1 2 840 113549 1 9 16 2 12 signingCertificate }
  CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE            = 2540;
  CRYPT_CERTINFO_CMS_SIGNINGCERT_CERTS             = 2541; { certs.essCertID.certHash }
  CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES          = 2542; { policies.policyInformation.policyIdentifier }

  { 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo }
  CRYPT_CERTINFO_CMS_SPCAGENCYINFO                 = 2543;
  CRYPT_CERTINFO_CMS_SPCAGENCYURL                  = 2544; { spcAgencyInfo.url }

  { 1 3 6 1 4 1 311 2 1 11 spcStatementType }
  CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE              = 2545;
  CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING = 2546; { individualCodeSigning }
  CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING = 2547; { commercialCodeSigning }

  { 1 3 6 1 4 1 311 2 1 12 spcOpusInfo }
  CRYPT_CERTINFO_CMS_SPCOPUSINFO                   = 2548;

  { Used internally }
  CRYPT_CERTINFO_LAST                              = 2549;
  CRYPT_KEYSETINFO_FIRST                           = 3000;

  {*******************}
  { Keyset attributes }
  {*******************}

  CRYPT_KEYSETINFO_QUERY                           = 3001; { Keyset query }

  { Used internally }
  CRYPT_KEYSETINFO_LAST                            = 3002;
  CRYPT_DEVINFO_FIRST                              = 4000;

  {*******************}
  { Device attributes }
  {*******************}

  CRYPT_DEVINFO_INITIALISE                         = 4001; { Initialise device for use }
  CRYPT_DEVINFO_INITIALIZE                         = 4001; {  = CRYPT_DEVINFO_INITIALISE  }
  CRYPT_DEVINFO_AUTHENT_USER                       = 4002; { Authenticate user to device }
  CRYPT_DEVINFO_AUTHENT_SUPERVISOR                 = 4003; { Authenticate supervisor to dev.}
  CRYPT_DEVINFO_SET_AUTHENT_USER                   = 4004; { Set user authent.value }
  CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR             = 4005; { Set supervisor auth.val.}
  CRYPT_DEVINFO_ZEROISE                            = 4006; { Zeroise device }
  CRYPT_DEVINFO_ZEROIZE                            = 4006; {  = CRYPT_DEVINFO_ZEROISE  }

  { Used internally }
  CRYPT_DEVINFO_LAST                               = 4007;
  CRYPT_ENVINFO_FIRST                              = 5000;

  {*********************}
  { Envelope attributes }
  {*********************}

  { Pseudo-information on an envelope or meta-information which is used to
  control the way data in an envelope is processed }
  CRYPT_ENVINFO_DATASIZE                           = 5001; { Data size information }
  CRYPT_ENVINFO_COMPRESSION                        = 5002; { Compression information }
  CRYPT_ENVINFO_CONTENTTYPE                        = 5003; { Inner CMS content type }
  CRYPT_ENVINFO_DETACHEDSIGNATURE                  = 5004; { Generate CMS detached signature }
  CRYPT_ENVINFO_SIGNATURE_RESULT                   = 5005; { Signature check result }
  CRYPT_ENVINFO_CURRENT_COMPONENT                  = 5006; { Env.information cursor management }

  { Resources required for enveloping/deenveloping }
  CRYPT_ENVINFO_PASSWORD                           = 5007; { User password }
  CRYPT_ENVINFO_KEY                                = 5008; { Conventional encryption key }
  CRYPT_ENVINFO_SIGNATURE                          = 5009; { Signature/signature check key }
  CRYPT_ENVINFO_SIGNATURE_EXTRADATA                = 5010; { Extra information added to CMS sigs }
  CRYPT_ENVINFO_PUBLICKEY                          = 5011; { PKC encryption key }
  CRYPT_ENVINFO_PRIVATEKEY                         = 5012; { PKC decryption key }
  CRYPT_ENVINFO_ORIGINATOR                         = 5013; { Originator info/key }
  CRYPT_ENVINFO_SESSIONKEY                         = 5014; { Session key }
  CRYPT_ENVINFO_HASH                               = 5015; { Hash algorithm }
  CRYPT_ENVINFO_MAC                                = 5016; { MAC key }

  { Keysets used to retrieve keys needed for enveloping/deenveloping }
  CRYPT_ENVINFO_KEYSET_SIGCHECK                    = 5017; { Signature check keyset }
  CRYPT_ENVINFO_KEYSET_ENCRYPT                     = 5018; { PKC encryption keyset }
  CRYPT_ENVINFO_KEYSET_DECRYPT                     = 5019; { PKC decryption keyset }

  { Used internally }
  CRYPT_ENVINFO_LAST                               = 5020;
  CRYPT_SESSINFO_FIRST                             = 6000;

  {********************}
  { Session attributes }
  {********************}

  { Pseudo-information on a session or meta-information which is used to
  control the way a session is managed }

  { Pseudo-information about the session }
  CRYPT_SESSINFO_ACTIVE                            = 6001; { Whether session is active }

  { Security-related information }
  CRYPT_SESSINFO_USERNAME                          = 6002; { User name }
  CRYPT_SESSINFO_PASSWORD                          = 6003; { Password }

  { Client/server information }
  CRYPT_SESSINFO_SERVER                            = 6004; { Server name }
  CRYPT_SESSINFO_SERVER_PORT                       = 6005; { Server port number }

  { Used internally for range checking }
  CRYPT_SESSINFO_LAST                              = 6006;
  CRYPT_ATTRIBUTE_LAST                             = 6006; {  = CRYPT_SESSINFO_LAST  }

  {****************************************************************************
  *                                                                         *
  *                     Attribute Subtypes and Related Values               *
  *                                                                         *
  ****************************************************************************}

  {  Flags for the X.509v3 keyUsage extension  }

  CRYPT_KEYUSAGE_NONE                              = $000;
  CRYPT_KEYUSAGE_DIGITALSIGNATURE                  = $001;
  CRYPT_KEYUSAGE_NONREPUDIATION                    = $002;
  CRYPT_KEYUSAGE_KEYENCIPHERMENT                   = $004;
  CRYPT_KEYUSAGE_DATAENCIPHERMENT                  = $008;
  CRYPT_KEYUSAGE_KEYAGREEMENT                      = $010;
  CRYPT_KEYUSAGE_KEYCERTSIGN                       = $020;
  CRYPT_KEYUSAGE_CRLSIGN                           = $040;
  CRYPT_KEYUSAGE_ENCIPHERONLY                      = $080;
  CRYPT_KEYUSAGE_DECIPHERONLY                      = $100;
  CRYPT_KEYUSAGE_LAST                              = $200; {  Last possible value  }

  {  X.509v3 cRLReason codes  }

  CRYPT_CRLREASON_UNSPECIFIED                      = 0;
  CRYPT_CRLREASON_KEYCOMPROMISE                    = 1;
  CRYPT_CRLREASON_CACOMPROMISE                     = 2;
  CRYPT_CRLREASON_AFFILIATIONCHANGED               = 3;
  CRYPT_CRLREASON_SUPERSEDED                       = 4;
  CRYPT_CRLREASON_CESSATIONOFOPERATION             = 5;
  CRYPT_CRLREASON_CERTIFICATEHOLD                  = 6;
  CRYPT_CRLREASON_REMOVEFROMCRL                    = 8;
  CRYPT_CRLREASON_LAST                             = 9;

  {  X.509v3 CRL reason flags.  These identify the same thing as the cRLReason
     codes but allow for multiple reasons to be specified.  Note that these
     don't follow the X.509 naming since in that scheme the enumerated types
     and bitflags have the same name  }

  CRYPT_CRLREASONFLAG_UNUSED                       = $001;
  CRYPT_CRLREASONFLAG_KEYCOMPROMISE                = $002;
  CRYPT_CRLREASONFLAG_CACOMPROMISE                 = $004;
  CRYPT_CRLREASONFLAG_AFFILIATIONCHANGED           = $008;
  CRYPT_CRLREASONFLAG_SUPERSEDED                   = $010;
  CRYPT_CRLREASONFLAG_CESSATIONOFOPERATION         = $020;
  CRYPT_CRLREASONFLAG_CERTIFICATEHOLD              = $040;
  CRYPT_CRLREASONFLAG_LAST                         = $080; {  Last poss.value  }

  {  X.509v3 CRL holdInstruction codes  }

  CRYPT_HOLDINSTRUCTION_NONE                       = 0;
  CRYPT_HOLDINSTRUCTION_CALLISSUER                 = 1;
  CRYPT_HOLDINSTRUCTION_REJECT                     = 2;
  CRYPT_HOLDINSTRUCTION_PICKUPTOKEN                = 3;
  CRYPT_HOLDINSTRUCTION_LAST                       = 4;

  {  Flags for the Netscape netscape-cert-type extension  }

  CRYPT_NS_CERTTYPE_SSLCLIENT                      = $001;
  CRYPT_NS_CERTTYPE_SSLSERVER                      = $002;
  CRYPT_NS_CERTTYPE_SMIME                          = $004;
  CRYPT_NS_CERTTYPE_OBJECTSIGNING                  = $008;
  CRYPT_NS_CERTTYPE_RESERVED                       = $010;
  CRYPT_NS_CERTTYPE_SSLCA                          = $020;
  CRYPT_NS_CERTTYPE_SMIMECA                        = $040;
  CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA                = $080;
  CRYPT_NS_CERTTYPE_LAST                           = $100; {  Last possible value  }

  {  Flags for the SET certificate-type extension  }

  CRYPT_SET_CERTTYPE_CARD                          = $001;
  CRYPT_SET_CERTTYPE_MER                           = $002;
  CRYPT_SET_CERTTYPE_PGWY                          = $004;
  CRYPT_SET_CERTTYPE_CCA                           = $008;
  CRYPT_SET_CERTTYPE_MCA                           = $010;
  CRYPT_SET_CERTTYPE_PCA                           = $020;
  CRYPT_SET_CERTTYPE_GCA                           = $040;
  CRYPT_SET_CERTTYPE_BCA                           = $080;
  CRYPT_SET_CERTTYPE_RCA                           = $100;
  CRYPT_SET_CERTTYPE_ACQ                           = $200;
  CRYPT_SET_CERTTYPE_LAST                          = $400; {  Last possible value  }

  {  CMS contentType values  }

type
  CRYPT_CONTENT_TYPE = (CRYPT_CONTENT_NONE, CRYPT_CONTENT_DATA,
    CRYPT_CONTENT_SIGNEDDATA, CRYPT_CONTENT_ENVELOPEDDATA,
    CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
    CRYPT_CONTENT_DIGESTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA,
    CRYPT_CONTENT_COMPRESSEDDATA,
    CRYPT_CONTENT_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_LAST

    );

  {  ESS securityClassification codes  }

const
  CRYPT_CLASSIFICATION_UNMARKED                    = 0;
  CRYPT_CLASSIFICATION_UNCLASSIFIED                = 1;
  CRYPT_CLASSIFICATION_RESTRICTED                  = 2;
  CRYPT_CLASSIFICATION_CONFIDENTIAL                = 3;
  CRYPT_CLASSIFICATION_SECRET                      = 4;
  CRYPT_CLASSIFICATION_TOP_SECRET                  = 5;
  CRYPT_CLASSIFICATION_LAST                        = 255;

  {  The certificate export format type, which defines the format in which a
     certificate object is exported  }

type
  CRYPT_CERTFORMAT_TYPE = (
    CRYPT_CERTFORMAT_NONE,                           {  No certificate format  }
    CRYPT_CERTFORMAT_CERTIFICATE,                    {  DER-encoded certificate  }
    CRYPT_CERTFORMAT_CERTCHAIN,                      {  PKCS #7 certificate chain  }
    CRYPT_CERTFORMAT_TEXT_CERTIFICATE,               {  base-64 wrapped cert  }
    CRYPT_CERTFORMAT_TEXT_CERTCHAIN,                 {  base-64 wrapped cert chain  }
    CRYPT_CERTFORMAT_LAST                            {  Last possible cert.format type  }

    );

  {  Key ID types  }

  CRYPT_KEYID_TYPE = (
    CRYPT_KEYID_NONE,                                {  No key ID type  }
    CRYPT_KEYID_NAME,                                {  Key owner name  }
    CRYPT_KEYID_EMAIL,                               {  Key owner email address  }
    CRYPT_KEYID_LAST                                 {  Last possible key ID type  }

    );

  {  Data format types  }

  CRYPT_FORMAT_TYPE = (
    CRYPT_FORMAT_NONE,                               {  No format type  }
    CRYPT_FORMAT_AUTO,                               {  Deenv, auto-determine type  }
    CRYPT_FORMAT_CRYPTLIB,                           {  cryptlib native format  }
    CRYPT_FORMAT_CMS,                                {  PKCS #7 / CMS / S/MIME format  }
    CRYPT_FORMAT_SMIME,                              {  As CMS with MSG-specific behaviour  }
    CRYPT_FORMAT_PGP,                                {  PGP format  }
    CRYPT_FORMAT_SSH,                                {  SSH format  }
    CRYPT_FORMAT_SSL,                                {  SSL format  }
    CRYPT_FORMAT_TLS,                                {  TLS format  }
    CRYPT_FORMAT_LAST                                {  Last possible format type  }
    );

const
    CRYPT_FORMAT_PKCS7: CRYPT_FORMAT_TYPE = CRYPT_FORMAT_CMS;

  {  The encryption object types  }

type
  CRYPT_OBJECT_TYPE = (
    CRYPT_OBJECT_NONE,                               {  No object type  }
    CRYPT_OBJECT_ENCRYPTED_KEY,                      {  Conventionally encrypted key  }
    CRYPT_OBJECT_PKCENCRYPTED_KEY,                   {  PKC-encrypted key  }
    CRYPT_OBJECT_KEYAGREEMENT,                       {  Key agreement information  }
    CRYPT_OBJECT_SIGNATURE,                          {  Signature  }
    CRYPT_OBJECT_LAST                                {  Last possible object type  }

    );

  {  Object/attribute error type information  }

  CRYPT_ERRTYPE_TYPE = (
    CRYPT_ERRTYPE_NONE,                              {  No error information  }
    CRYPT_ERRTYPE_ATTR_SIZE,                         {  Attribute data too small or large  }
    CRYPT_ERRTYPE_ATTR_VALUE,                        {  Attribute value is invalid  }
    CRYPT_ERRTYPE_ATTR_ABSENT,                       {  Required attribute missing  }
    CRYPT_ERRTYPE_ATTR_PRESENT,                      {  Non-allowed attribute present  }
    CRYPT_ERRTYPE_CONSTRAINT,                        {  Cert: Constraint violation in object  }
    CRYPT_ERRTYPE_ISSUERCONSTRAINT,                  {  Cert: Constraint viol.in issuing cert  }
    CRYPT_ERRTYPE_LAST                               {  Last possible error info type  }

    );

  {****************************************************************************
  *                                                                         *
  *                             General Constants                           *
  *                                                                         *
  ****************************************************************************}

  {  The maximum user key size - 2048 bits  }

const
  CRYPT_MAX_KEYSIZE                                = 256;

  {  The maximum IV size - 256 bits  }

  CRYPT_MAX_IVSIZE                                 = 32;

  {  The maximum public-key component size - 4096 bits  }

  CRYPT_MAX_PKCSIZE                                = 512;

  {  The maximum hash size - 256 bits  }

  CRYPT_MAX_HASHSIZE                               = 32;

  {  The maximum size of a text string (eg key owner name)  }

  CRYPT_MAX_TEXTSIZE                               = 64;

  {  A magic value indicating that the default setting for this parameter
     should be used  }

  CRYPT_USE_DEFAULT                                = -10;

  {  A magic value for unused parameters  }

  CRYPT_UNUSED                                     = -11;

  {  Whether the PKC key is a public or private key  }

  CRYPT_KEYTYPE_PRIVATE                            = 0;
  CRYPT_KEYTYPE_PUBLIC                             = 1;

  {  The type of information polling to perform to get random seed information  }

  CRYPT_RANDOM_FASTPOLL                            = -10;
  CRYPT_RANDOM_SLOWPOLL                            = -11;

  {  Cursor positioning codes for certificate/CRL extensions  }

  CRYPT_CURSOR_FIRST                               = -20;
  CRYPT_CURSOR_PREVIOUS                            = -21;
  CRYPT_CURSOR_NEXT                                = -22;
  CRYPT_CURSOR_LAST                                = -23;

  {  Options passed to cryptOpenKeyset() and cryptOpenKeysetEx()  }

type
  CRYPT_KEYOPT_TYPE = (
    CRYPT_KEYOPT_NONE,                               {  No options  }
    CRYPT_KEYOPT_READONLY,                           {  Open keyset in read-only mode  }
    CRYPT_KEYOPT_CREATE,                             {  Create a new keyset  }
    CRYPT_KEYOPT_LAST                                {  Last possible key option type  }

    );

  {  Macros to convert to and from the bit counts used for some encryption
     parameters  }

  { C-macro not translated to Delphi code:
  {   #define bitsToBytes(bits) ( ( ( bits ) + 7 ) >> 3 ) }
  { C-macro not translated to Delphi code:
  {   #define bytesToBits(bytes)    ( ( bytes ) << 3 ) }

  {  The various cryptlib objects - these are just integer handles  }

  CRYPT_CERTIFICATE = Integer;
  CRYPT_CONTEXT = Integer;
  CRYPT_DEVICE = Integer;
  CRYPT_ENVELOPE = Integer;
  CRYPT_KEYSET = Integer;
  CRYPT_SESSION = Integer;

  {  Sometimes we don't know the exact type of a cryptlib object, so we use a
     generic handle type to identify it  }

  CRYPT_HANDLE = Integer;

  {****************************************************************************
  *                                                                         *
  *                         Encryption Data Structures                      *
  *                                                                         *
  ****************************************************************************}

  {  Results returned from the encryption capability query  }

  CRYPT_QUERY_INFO = record
    { The algorithm, encryption mode, and algorithm and mode names }
    cryptAlgo: CRYPT_ALGO;                           { The encryption algorithm }
    cryptMode: CRYPT_MODE;                           { The encryption mode }
    algoName: array[0..CRYPT_MAX_TEXTSIZE - 1] of char; { The algorithm name }
    modeName: array[0..CRYPT_MAX_TEXTSIZE - 1] of char; { The mode name }

    { The algorithm parameters }
    blockSize: Integer;                              { The block size of the algorithm }
    minKeySize: Integer;                             { Minimum key size in bytes }
    keySize: Integer;                                { Recommended key size in bytes }
    maxKeySize: Integer;                             { Maximum key size in bytes }
    ivSize: Integer;                                 { IV size in bytes }

  end;

  {  Results returned from the encryption object query.  These provide
     information on the objects created by cryptExportKey()/
     cryptCreateSignature()  }

  CRYPT_OBJECT_INFO = record
    { The object type }
    objectType: CRYPT_OBJECT_TYPE;                   { The object type }

    { The encryption algorithm and mode }
    cryptAlgo: CRYPT_ALGO;                           { The encryption algorithm }
    cryptMode: CRYPT_MODE;                           { The encryption mode }

    { The hash algorithm for Signature objects }
    hashAlgo: CRYPT_ALGO;                            { Hash algorithm }

    { The salt for derived keys }
    salt: array[0..CRYPT_MAX_HASHSIZE - 1] of byte;
    saltSize: Integer;

  end;

  {  Key information for the public-key encryption algorithms.  These fields
     are not accessed directly, but can be manipulated with the init/set/
     destroyComponents() macros  }

  CRYPT_PKCINFO_RSA = record
    { Status information }
    isPublicKey: Integer;                            { Whether this is a public or private key }

    { Public components }
    n: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Modulus }
    nLen: Integer;                                   { Length of modulus in bits }
    e: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Public exponent }
    eLen: Integer;                                   { Length of public exponent in bits }

    { Private components }
    d: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Private exponent }
    dLen: Integer;                                   { Length of private exponent in bits }
    p: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Prime factor 1 }
    pLen: Integer;                                   { Length of prime factor 1 in bits }
    q: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Prime factor 2 }
    qLen: Integer;                                   { Length of prime factor 2 in bits }
    u: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Mult.inverse of q, mod p }
    uLen: Integer;                                   { Length of private exponent in bits }
    e1: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;     { Private exponent 1 (PKCS) }
    e1Len: Integer;                                  { Length of private exponent in bits }
    e2: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;     { Private exponent 2 (PKCS) }
    e2Len: Integer;                                  { Length of private exponent in bits }

  end;

  CRYPT_PKCINFO_DLP = record
    { Status information }
    isPublicKey: Integer;                            { Whether this is a public or private key }

    { Public components }
    p: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Prime modulus }
    pLen: Integer;                                   { Length of prime modulus in bits }
    q: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Prime divisor }
    qLen: Integer;                                   { Length of prime divisor in bits }
    g: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { h^( ( p - 1 ) / q ) mod p }
    gLen: Integer;                                   { Length of g in bits }
    y: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Public random integer }
    yLen: Integer;                                   { Length of public integer in bits }

    { Private components }
    x: array[0..CRYPT_MAX_PKCSIZE - 1] of byte;      { Private random integer }
    xLen: Integer;                                   { Length of private integer in bits }

  end;

  {  Macros to initialise and destroy the structure which stores the components
     of a public key  }

  { C-macro not translated to Delphi code:
  {   #define cryptInitComponents( componentInfo, componentKeyType )
   < memset( componentInfo, 0, sizeof( *componentInfo ) );
     componentInfo##->isPublicKey = ( componentKeyType ? TRUE : FALSE ); > }

  { C-macro not translated to Delphi code:
  {   #define cryptDestroyComponents( componentInfo )
   memset( componentInfo, 0, sizeof( *componentInfo ) ) }

  {  Macros to set a component of a public key  }

  { C-macro not translated to Delphi code:
  {   #define cryptSetComponent( destination, source, length )
   < memcpy( destination, source, bitsToBytes( length ) );
     destination##Len = length; > }

  {****************************************************************************
  *                                                                         *
  *                             Status Codes                                *
  *                                                                         *
  ****************************************************************************}

  {  No error in function call  }

const
  CRYPT_OK                                         = 0; {  No error  }

  {  Error in parameters passed to function  }

  CRYPT_ERROR_PARAM1                               = -1; {  Bad argument, parameter 1  }
  CRYPT_ERROR_PARAM2                               = -2; {  Bad argument, parameter 2  }
  CRYPT_ERROR_PARAM3                               = -3; {  Bad argument, parameter 3  }
  CRYPT_ERROR_PARAM4                               = -4; {  Bad argument, parameter 4  }
  CRYPT_ERROR_PARAM5                               = -5; {  Bad argument, parameter 5  }
  CRYPT_ERROR_PARAM6                               = -6; {  Bad argument, parameter 6  }
  CRYPT_ERROR_PARAM7                               = -7; {  Bad argument, parameter 7  }

  {  Errors due to insufficient resources  }

  CRYPT_ERROR_MEMORY                               = -10; {  Out of memory  }
  CRYPT_ERROR_NOTINITED                            = -11; {  Data has not been initialised  }
  CRYPT_ERROR_INITED                               = -12; {  Data has already been init'd  }
  CRYPT_ERROR_NOSECURE                             = -13; {  Opn.not avail.at requested sec.level  }
  CRYPT_ERROR_RANDOM                               = -14; {  No reliable random data available  }
  CRYPT_ERROR_FAILED                               = -15; {  Operation failed  }

  {  Security violations  }

  CRYPT_ERROR_NOTAVAIL                             = -20; {  This type of opn.not available  }
  CRYPT_ERROR_PERMISSION                           = -21; {  No permiss.to perform this operation  }
  CRYPT_ERROR_WRONGKEY                             = -22; {  Incorrect key used to decrypt data  }
  CRYPT_ERROR_INCOMPLETE                           = -23; {  Operation incomplete/still in progress  }
  CRYPT_ERROR_COMPLETE                             = -24; {  Operation complete/can't continue  }
  CRYPT_ERROR_BUSY                                 = -25; {  Resource in use by async operation  }
  CRYPT_ERROR_INVALID                              = -26; {  Invalid/inconsistent information  }
  CRYPT_ERROR_SIGNALLED                            = -27; {  Resource destroyed by extnl.event  }

  {  High-level function errors  }

  CRYPT_ERROR_OVERFLOW                             = -30; {  Resources/space exhausted  }
  CRYPT_ERROR_UNDERFLOW                            = -31; {  Not enough data available  }
  CRYPT_ERROR_BADDATA                              = -32; {  Bad/unrecognised data format  }
  CRYPT_ERROR_SIGNATURE                            = -33; {  Signature/integrity check failed  }

  {  Data access function errors  }

  CRYPT_ERROR_OPEN                                 = -40; {  Cannot open object  }
  CRYPT_ERROR_READ                                 = -41; {  Cannot read item from object  }
  CRYPT_ERROR_WRITE                                = -42; {  Cannot write item to object  }
  CRYPT_ERROR_NOTFOUND                             = -43; {  Requested item not found in object  }
  CRYPT_ERROR_DUPLICATE                            = -44; {  Item already present in object  }

  {  Data enveloping errors  }

  CRYPT_ENVELOPE_RESOURCE                          = -50; {  Need resource to proceed  }

  {  Macros to examine return values  }

  { C-macro not translated to Delphi code:
  {   #define cryptStatusError( status )    ( ( status ) < CRYPT_OK ) }
  { C-macro not translated to Delphi code:
  {   #define cryptStatusOK( status )       ( ( status ) == CRYPT_OK ) }

  {****************************************************************************
  *                                                                         *
  *                                 General Functions                       *
  *                                                                         *
  ****************************************************************************}

  {  The following is necessary to stop C++ name mangling  }

  {  Initialise and shut down cryptlib  }

function cryptInit: Integer;
stdcall; external 'CL32.DLL';

function cryptInitEx: Integer;
stdcall; external 'CL32.DLL';

function cryptEnd: Integer;
stdcall; external 'CL32.DLL';

{  Query cryptlibs capabilities  }

function cryptQueryCapability(const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE;
  var cryptQueryInfo: CRYPT_QUERY_INFO): Integer;
stdcall; external 'CL32.DLL';

{  Create and destroy an encryption context  }

function cryptCreateContext(var cryptContext: CRYPT_CONTEXT;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE): Integer;
stdcall; external 'CL32.DLL';

function cryptDestroyContext(const cryptContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

{  Generic "destroy an object" function  }

function cryptDestroyObject(const cryptObject: CRYPT_HANDLE): Integer;
stdcall; external 'CL32.DLL';

{  Generate a key into a context  }

function cryptGenerateKey(const cryptContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptGenerateKeyEx(const cryptContext: CRYPT_CONTEXT;
  const keyLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptGenerateKeyAsync(const cryptContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptGenerateKeyAsyncEx(const cryptContext: CRYPT_CONTEXT;
  const keyLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptAsyncQuery(const cryptContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptAsyncCancel(const cryptContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

{  Encrypt/decrypt/hash a block of memory  }

function cryptEncrypt(const cryptContext: CRYPT_CONTEXT;
  buffer: Pointer;
  const length: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptDecrypt(const cryptContext: CRYPT_CONTEXT;
  buffer: Pointer;
  const length: Integer): Integer;
stdcall; external 'CL32.DLL';

{  Get/set/delete attribute functions  }

function cryptSetAttribute(const cryptHandle: CRYPT_HANDLE;
  const attributeType: CRYPT_ATTRIBUTE_TYPE;
  const value: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptSetAttributeString(const cryptHandle: CRYPT_HANDLE;
  const attributeType: CRYPT_ATTRIBUTE_TYPE;
  const value: Pointer;
  const valueLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptGetAttribute(const cryptHandle: CRYPT_HANDLE;
  const attributeType: CRYPT_ATTRIBUTE_TYPE;
  var value: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptGetAttributeString(const cryptHandle: CRYPT_HANDLE;
  const attributeType: CRYPT_ATTRIBUTE_TYPE;
  value: Pointer;
  var valueLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptDeleteAttribute(const cryptHandle: CRYPT_HANDLE;
  const attributeType: CRYPT_ATTRIBUTE_TYPE): Integer;
stdcall; external 'CL32.DLL';

{  Oddball functions: Add random data to the pool, query an encoded signature
   or key data.  These are due to be replaced once a suitable alternative can
   be found  }

function cryptAddRandom(const randomData: Pointer;
  const randomDataLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptQueryObject(const objectData: Pointer;
  var cryptObjectInfo: CRYPT_OBJECT_INFO): Integer;
stdcall; external 'CL32.DLL';

{****************************************************************************
*                                                                           *
*                           Mid-level Encryption Functions                  *
*                                                                           *
****************************************************************************}

{  Export and import an encrypted session key  }

function cryptExportKey(encryptedKey: Pointer;
  var encryptedKeyLength: Integer;
  const exportKey: CRYPT_HANDLE;
  const sessionKeyContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptExportKeyEx(encryptedKey: Pointer;
  var encryptedKeyLength: Integer;
  const formatType: CRYPT_FORMAT_TYPE;
  const exportKey: CRYPT_HANDLE;
  const sessionKeyContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptImportKey(const encryptedKey: Pointer;
  const importKey: CRYPT_CONTEXT;
  const sessionKeyContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptImportKeyEx(const encryptedKey: Pointer;
  const importKey: CRYPT_CONTEXT;
  const sessionKeyContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

{  Create and check a digital signature  }

function cryptCreateSignature(signature: Pointer;
  var signatureLength: Integer;
  const signContext: CRYPT_CONTEXT;
  const hashContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptCreateSignatureEx(signature: Pointer;
  var signatureLength: Integer;
  const formatType: CRYPT_FORMAT_TYPE;
  const signContext: CRYPT_CONTEXT;
  const hashContext: CRYPT_CONTEXT;
  const extraData: CRYPT_CERTIFICATE): Integer;
stdcall; external 'CL32.DLL';

function cryptCheckSignature(const signature: Pointer;
  const sigCheckKey: CRYPT_HANDLE;
  const hashContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptCheckSignatureEx(const signature: Pointer;
  const sigCheckKey: CRYPT_HANDLE;
  const hashContext: CRYPT_CONTEXT;
  var extraData: CRYPT_HANDLE): Integer;
stdcall; external 'CL32.DLL';

{****************************************************************************
*                                                                           *
*                                   Keyset Functions                        *
*                                                                           *
****************************************************************************}

{  Open and close a keyset  }

function cryptKeysetOpen(var keyset: CRYPT_KEYSET;
  const keysetType: CRYPT_KEYSET_TYPE;
  const name: PChar;
  const options: CRYPT_KEYOPT_TYPE): Integer;
stdcall; external 'CL32.DLL';

function cryptKeysetOpenEx(var keyset: CRYPT_KEYSET;
  const keysetType: CRYPT_KEYSET_TYPE;
  const name: PChar;
  const param1: PChar;
  const param2: PChar;
  const param3: PChar;
  const options: CRYPT_KEYOPT_TYPE): Integer;
stdcall; external 'CL32.DLL';

function cryptKeysetClose(const keyset: CRYPT_KEYSET): Integer;
stdcall; external 'CL32.DLL';

{  Get a key from a keyset  }

function cryptGetPublicKey(const keyset: CRYPT_KEYSET;
  var cryptContext: CRYPT_CONTEXT;
  const keyIDtype: CRYPT_KEYID_TYPE;
  const keyID: Pointer): Integer;
stdcall; external 'CL32.DLL';

function cryptGetPrivateKey(const keyset: CRYPT_KEYSET;
  var cryptContext: CRYPT_CONTEXT;
  const keyIDtype: CRYPT_KEYID_TYPE;
  const keyID: Pointer;
  const password: Pointer): Integer;
stdcall; external 'CL32.DLL';

{  Add/delete a key to/from a keyset  }

function cryptAddPublicKey(const keyset: CRYPT_KEYSET;
  const certificate: CRYPT_CERTIFICATE): Integer;
stdcall; external 'CL32.DLL';

function cryptAddPrivateKey(const keyset: CRYPT_KEYSET;
  const cryptKey: CRYPT_HANDLE;
  const password: Pointer): Integer;
stdcall; external 'CL32.DLL';

function cryptDeleteKey(const keyset: CRYPT_KEYSET;
  const keyIDtype: CRYPT_KEYID_TYPE;
  const keyID: Pointer): Integer;
stdcall; external 'CL32.DLL';

{****************************************************************************
*                                                                           *
*                               Certificate Functions                       *
*                                                                           *
****************************************************************************}

{  Create/destroy a certificate  }

function cryptCreateCert(var certificate: CRYPT_CERTIFICATE;
  const certType: CRYPT_CERTTYPE_TYPE): Integer;
stdcall; external 'CL32.DLL';

function cryptDestroyCert(const certificate: CRYPT_CERTIFICATE): Integer;
stdcall; external 'CL32.DLL';

{  Get/add/delete certificate extensions  }

function cryptGetCertExtension(const cryptHandle: CRYPT_HANDLE;
  const oid: PChar;
  var criticalFlag: Integer;
  extension: Pointer;
  var extensionLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptAddCertExtension(const certificate: CRYPT_CERTIFICATE;
  const oid: PChar;
  const criticalFlag: Integer;
  const extension: Pointer;
  const extensionLength: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptDeleteCertExtension(const certificate: CRYPT_CERTIFICATE;
  const oid: PChar): Integer;
stdcall; external 'CL32.DLL';

{  Sign/sig.check a certificate/certification request  }

function cryptSignCert(const certificate: CRYPT_CERTIFICATE;
  const signContext: CRYPT_CONTEXT): Integer;
stdcall; external 'CL32.DLL';

function cryptCheckCert(const certificate: CRYPT_CERTIFICATE;
  const sigCheckKey: CRYPT_HANDLE): Integer;
stdcall; external 'CL32.DLL';

{  Import/export a certificate/certification request  }

function cryptImportCert(const certObject: Pointer;
  const certObjectLength: Integer;
  var certificate: CRYPT_CERTIFICATE): Integer;
stdcall; external 'CL32.DLL';

function cryptExportCert(certObject: Pointer;
  var certObjectLength: Integer;
  const certFormatType: CRYPT_CERTFORMAT_TYPE;
  const certificate: CRYPT_CERTIFICATE): Integer;
stdcall; external 'CL32.DLL';

{****************************************************************************
*                                                                           *
*                           Envelope and Session Functions                  *
*                                                                           *
****************************************************************************}

{  Create/destroy an envelope  }

function cryptCreateEnvelope(var envelope: CRYPT_ENVELOPE;
  const formatType: CRYPT_FORMAT_TYPE): Integer;
stdcall; external 'CL32.DLL';

function cryptDestroyEnvelope(const envelope: CRYPT_ENVELOPE): Integer;
stdcall; external 'CL32.DLL';

{  Create/destroy a session  }

function cryptCreateSession(var session: CRYPT_SESSION;
  const formatType: CRYPT_FORMAT_TYPE): Integer;
stdcall; external 'CL32.DLL';

function cryptDestroySession(const session: CRYPT_SESSION): Integer;
stdcall; external 'CL32.DLL';

{  Add/remove data to/from and envelope or session  }

function cryptPushData(const envelope: CRYPT_HANDLE;
  const buffer: Pointer;
  const length: Integer;
  var bytesCopied: Integer): Integer;
stdcall; external 'CL32.DLL';

function cryptPopData(const envelope: CRYPT_HANDLE;
  buffer: Pointer;
  const length: Integer;
  var bytesCopied: Integer): Integer;
stdcall; external 'CL32.DLL';

{****************************************************************************
*                                                                           *
*                               Device Functions                            *
*                                                                           *
****************************************************************************}

{  Open and close a device  }

function cryptDeviceOpen(var device: CRYPT_DEVICE;
  const deviceType: CRYPT_DEVICE_TYPE;
  const name: PChar): Integer;
stdcall; external 'CL32.DLL';

function cryptDeviceClose(const device: CRYPT_DEVICE): Integer;
stdcall; external 'CL32.DLL';

{  Query a devices capabilities  }

function cryptDeviceQueryCapability(const device: CRYPT_DEVICE;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE;
  var cryptQueryInfo: CRYPT_QUERY_INFO): Integer;
stdcall; external 'CL32.DLL';

{  Create an encryption context via the device  }

function cryptDeviceCreateContext(const device: CRYPT_DEVICE;
  var cryptContext: CRYPT_CONTEXT;
  const cryptAlgo: CRYPT_ALGO;
  const cryptMode: CRYPT_MODE): Integer;
stdcall; external 'CL32.DLL';

{  Peform a control function on the device.  This is a kludge extension to
   cryptSetAttributeString() which will be replaced by that function once
   a clean means of passing two sets of parameters is found  }

function cryptDeviceControlEx(const device: CRYPT_DEVICE;
  const controlType: CRYPT_ATTRIBUTE_TYPE;
  const data1: Pointer;
  const data1Length: Integer;
  const data2: Pointer;
  const data2Length: Integer): Integer;
stdcall; external 'CL32.DLL';

{****************************************************************************
*                                                                           *
*                       Delphi specific Functions                           *
*                                                                           *
****************************************************************************}

{ The function cryptPushPointer must be added to replace the C-function call
    cryptPushData(envelope, NULL, 0, NULL);
  Delphi equivalent for this function is:
    cryptPushPointer(envelope, nil, 0, nil);
  Maybe this is will be eliminated in one of the next beta's in cryptlib.
}

type
  PInteger = ^Integer;

function cryptPushPointer(const envelope: CRYPT_HANDLE;
  const buffer: Pointer;
  const length: Integer;
  bytesCopied: PInteger): Integer;
stdcall; external 'CL32.DLL' name 'cryptPushData';

implementation

{ no implementation code now }

end.


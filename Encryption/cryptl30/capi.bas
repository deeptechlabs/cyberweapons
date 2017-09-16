!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
This file hasn't been updated for awhile and apparently doesn't follow capi.h
in some areas, so it may not work as required with VB.  If someone wants to fix
it and send me the updated version I'd appreciate it.

One issue which has come up several times is that in some cases string/array
values seem to work when passed ByVal, and sometime when passed ByRef.  The
most likely case is that different versions of VB just happen to represent the
data in the correct format for the C code depending on which way the parameter
is declared, since strictly speaking neither ByVal or ByRef produce C-style
strings, but it appears that one of the two work for different versions of VB.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Attribute VB_Name = "capi"
Option Explicit

'  32 bit - all Integers defined as Long

Public Const CRYPT_KEYUSAGE_DIGITALSIGNATURE As Long = 1
Public Const CRYPT_KEYUSAGE_NONREPUDIATION As Long = 2
Public Const CRYPT_KEYUSAGE_KEYENCIPHERMENT As Long = 4
Public Const CRYPT_KEYUSAGE_DATAENCIPHERMENT As Long = 8
Public Const CRYPT_KEYUSAGE_KEYAGREEMENT As Long = 16
Public Const CRYPT_KEYUSAGE_KEYCERTSIGN  As Long = 32
Public Const CRYPT_KEYUSAGE_CRLSIGN As Long = 64
Public Const CRYPT_KEYUSAGE_ENCIPHERONLY As Long = 128
Public Const CRYPT_KEYUSAGE_DECIPHERONLY As Long = 256
Public Const CRYPT_KEYUSAGE_LAST As Long = 512  ' Last possible value

' Flags for the X.509v3 cRLReason extension
'
Public Const CRYPT_CRLREASON_UNSPECIFIED As Long = 1
Public Const CRYPT_CRLREASON_KEYCOMPROMISE As Long = 2
Public Const CRYPT_CRLREASON_CACOMPROMISE As Long = 4
Public Const CRYPT_CRLREASON_AFFILIATIONCHANGED As Long = 8
Public Const CRYPT_CRLREASON_SUPERSEDED As Long = 16
Public Const CRYPT_CRLREASON_CESSATIONOFOPERATION As Long = 32
Public Const CRYPT_CRLREASON_CERTIFICATEHOLD As Long = 64
Public Const CRYPT_CRLREASON_REMOVEFROMCRL As Long = 128
Public Const CRYPT_CRLREASON_LAST As Long = 256 ' Last possible value

' Flags for the Netscape netscape-cert-type extension
'
Public Const CRYPT_NS_CERTTYPE_SSLCLIENT As Long = 1
Public Const CRYPT_NS_CERTTYPE_SSLSERVER As Long = 2
Public Const CRYPT_NS_CERTTYPE_SMIME As Long = 4
Public Const CRYPT_NS_CERTTYPE_OBJECTSIGNING As Long = 8
Public Const CRYPT_NS_CERTTYPE_RESERVED As Long = 16
Public Const CRYPT_NS_CERTTYPE_SSLCA As Long = 32
Public Const CRYPT_NS_CERTTYPE_SMIMECA As Long = 64
Public Const CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA As Long = 128
Public Const CRYPT_NS_CERTTYPE_LAST As Long = 256       ' Last possible value

Public Const CRYPT_MAX_KEYSIZE      As Long = 256       ' The maximum user key size - 2048 bits
Public Const CRYPT_MAX_IVSIZE       As Long = 8         ' The maximum IV size - 64 bits
Public Const CRYPT_MAX_PKCSIZE      As Long = 512       ' The maximum public-key component size - 4096 bits
Public Const CRYPT_MAX_HASHSIZE     As Long = 32        ' The maximum hash size - 256 bits
Public Const CRYPT_MAX_TEXTSIZE     As Long = 64        ' The maximum size of a text string (eg key owner name)
Public Const CRYPT_USE_DEFAULT      As Long = -1        ' A magic value indicating that the default setting for this parameter
                                                        '   should be used
Public Const CRYPT_UNUSED           As Long = -2        ' A magic value for unused parameters
Public Const CRYPT_COMPONENTS_BIGENDIAN   As Long = 0   ' The endianness of the external components of the PKC key
Public Const CRYPT_COMPONENTS_LITTLENDIAN As Long = 1
Public Const CRYPT_KEYTYPE_PRIVATE  As Long = 0         ' Whether the PKC key is a public or private key
Public Const CRYPT_KEYTYPE_PUBLIC   As Long = 1
Public Const CRYPT_RANDOM_FASTPOLL  As Long = -1        ' The type of information polling to perform to get random seed information
Public Const CRYPT_RANDOM_SLOWPOLL  As Long = -2
Public Const CRYPT_KEYSET_GETFIRST  As Long = -10       ' Special key ID's for getFirst()/getNext() functionality in flat file
Public Const CRYPT_KEYSET_GETNEXT   As Long = -11       '  keysets
Public Const CRYPT_KEYUPDATE_BEGIN  As Long = -20       ' Special keyset contexts for begin/end bulk update functionality in
Public Const CRYPT_KEYUPDATE_END    As Long = -21       '  keysets

' Cursor positioning codes for certificate/CRL extensions
'
Public Const CRYPT_CURSOR_FIRST     As Long = -30
Public Const CRYPT_CURSOR_PREVIOUS  As Long = -31
Public Const CRYPT_CURSOR_NEXT      As Long = -32
Public Const CRYPT_CURSOR_LAST      As Long = -33

Public Const CRYPT_OK               As Long = 0         ' No error

' Internal errors
'
Public Const CRYPT_ERROR            As Long = -1        ' Nonspecific error
Public Const CRYPT_SELFTEST         As Long = -2        ' Failed self-test

' Error in parameters passed to function
'
Public Const CRYPT_BADPARM          As Long = -10       ' Generic bad argument to function
Public Const CRYPT_BADPARM1         As Long = -11       ' Bad argument, parameter 1
Public Const CRYPT_BADPARM2         As Long = -12       ' Bad argument, parameter 2
Public Const CRYPT_BADPARM3         As Long = -13       ' Bad argument, parameter 3
Public Const CRYPT_BADPARM4         As Long = -14       ' Bad argument, parameter 4
Public Const CRYPT_BADPARM5         As Long = -15       ' Bad argument, parameter 5
Public Const CRYPT_BADPARM6         As Long = -16       ' Bad argument, parameter 6
Public Const CRYPT_BADPARM7         As Long = -17       ' Bad argument, parameter 7
Public Const CRYPT_BADPARM8         As Long = -18       ' Bad argument, parameter 8
Public Const CRYPT_BADPARM9         As Long = -19       ' Bad argument, parameter 9
Public Const CRYPT_BADPARM10        As Long = -20       ' Bad argument, parameter 10

' Errors due to insufficient resources
'
Public Const CRYPT_NOMEM            As Long = -50       ' Out of memory
Public Const CRYPT_NOTINITED        As Long = -51       ' Data has not been initialised
Public Const CRYPT_INITED           As Long = -52       ' Data has already been initialised
Public Const CRYPT_NOALGO           As Long = -53       ' Algorithm unavailable
Public Const CRYPT_NOMODE           As Long = -54       ' Encryption mode unavailable
Public Const CRYPT_NOKEY            As Long = -55       ' Key not initialised
Public Const CRYPT_NOIV             As Long = -56       ' IV not initialised
Public Const CRYPT_NOLOCK           As Long = -57       ' Unable to lock pages in memory
Public Const CRYPT_NORANDOM         As Long = -58       ' No reliable random data available

' Security violations
'
Public Const CRYPT_NOTAVAIL         As Long = -100      ' Operation not available for this algo/mode
Public Const CRYPT_NOPERM           As Long = -101      ' No permiss.to perform this operation
Public Const CRYPT_WRONGKEY         As Long = -102      ' Incorrect key used to decrypt data
Public Const CRYPT_INCOMPLETE       As Long = -103      ' Operation incomplete/still in progress
Public Const CRYPT_COMPLETE         As Long = -104      ' Operation complete/can't continue
Public Const CRYPT_ORPHAN           As Long = -105      ' Contexts remained allocated
Public Const CRYPT_BUSY             As Long = -106      ' Resource in use by async operation
Public Const CRYPT_SIGNALLED        As Long = -107      ' Resource destroyed by external event

' High-level function errors
'
Public Const CRYPT_OVERFLOW         As Long = -150      ' Too much data supplied to function
Public Const CRYPT_UNDERFLOW        As Long = -151      ' Not enough data supplied to function
Public Const CRYPT_PKCCRYPT         As Long = -152      ' PKC en/decryption failed
Public Const CRYPT_BADDATA          As Long = -153      ' Bad data format in object
Public Const CRYPT_BADSIG           As Long = -154      ' Bad signature on data
Public Const CRYPT_INVALID          As Long = -155      ' Invalid/inconsistent information

' Data access function errors
'
Public Const CRYPT_DATA_OPEN        As Long = -200      ' Cannot open data object
Public Const CRYPT_DATA_READ        As Long = -201      ' Cannot read item from data object
Public Const CRYPT_DATA_WRITE       As Long = -202      ' Cannot write item to data object
Public Const CRYPT_DATA_NOTFOUND    As Long = -203      ' Requested item not found in data obj.
Public Const CRYPT_DATA_DUPLICATE   As Long = -204      ' Item already present in data object

' Data enveloping errors
'
Public Const CRYPT_ENVELOPE_RESOURCE As Long = -250     ' Need resource to proceed


'***************************************************************************
'                                                                          *
'                                    Encryption Algorithm and Object Types *
'                                                                          *
'***************************************************************************

' The encryption algorithms we can use
Enum CRYPT_ALGO
  ' No encryption
  CRYPT_ALGO_NONE                                 ' No encryption

  ' Conventional encryption
  CRYPT_ALGO_DES                                  ' DES
  CRYPT_ALGO_3DES                                 ' Triple DES
  CRYPT_ALGO_IDEA                                 ' IDEA
  CRYPT_ALGO_CAST                                 ' CAST-128
  CRYPT_ALGO_RC2                                  ' RC2
  CRYPT_ALGO_RC4                                  ' RC4
  CRYPT_ALGO_RC5                                  ' RC5
  CRYPT_ALGO_SAFER                                ' SAFER/SAFER-SK
  CRYPT_ALGO_BLOWFISH                             ' Blowfish
  CRYPT_ALGO_GOST                                 ' GOST 28147 (not implemented yet)
  CRYPT_ALGO_SKIPJACK                             ' It's only a matter of time...
  CRYPT_ALGO_MDCSHS = 99                          ' MDC/SHS - Deprecated

  ' Public-key encryption
  CRYPT_ALGO_DH = 100                             ' Diffie-Hellman
  CRYPT_ALGO_RSA                                  ' RSA
  CRYPT_ALGO_DSA                                  ' DSA
  CRYPT_ALGO_ELGAMAL                              ' ElGamal

  ' Hash algorithms
  CRYPT_ALGO_MD2 = 200                            ' MD2
  CRYPT_ALGO_MD4                                  ' MD4
  CRYPT_ALGO_MD5                                  ' MD5
  CRYPT_ALGO_SHA                                  ' SHA/SHA1
  CRYPT_ALGO_RIPEMD160                            ' RIPE-MD 160

  ' MAC's
  CRYPT_ALGO_HMAC_MD5 = 300                       ' HMAC-MD5
  CRYPT_ALGO_HMAC_SHA                             ' HMAC-SHA
  CRYPT_ALGO_HMAC_RIPEMD160                       ' HMAC-RIPEMD-160

  CRYPT_ALGO_LAST                                 ' Last possible crypt algo value

  ' In order that we can scan through a range of algorithms with
  '  cryptAlgoAvailable(), we define the following boundary points for each
  '  algorithm class
  CRYPT_ALGO_FIRST_CONVENTIONAL = CRYPT_ALGO_DES
  CRYPT_ALGO_LAST_CONVENTIONAL = CRYPT_ALGO_DH - 1
  CRYPT_ALGO_FIRST_PKC = CRYPT_ALGO_DH
  CRYPT_ALGO_LAST_PKC = CRYPT_ALGO_MD2 - 1
  CRYPT_ALGO_FIRST_HASH = CRYPT_ALGO_MD2
  CRYPT_ALGO_LAST_HASH = CRYPT_ALGO_HMAC_MD5 - 1
  CRYPT_ALGO_FIRST_MAC = CRYPT_ALGO_HMAC_MD5
  CRYPT_ALGO_LAST_MAC = CRYPT_ALGO_HMAC_MD5 + 99  ' End of mac algo.range
End Enum

' The encryption modes we can use
Enum CRYPT_MODE
  ' No encryption
  CRYPT_MODE_NONE                         ' No encryption (hashes and MAC's)

  ' Stream cipher modes
  CRYPT_MODE_STREAM                       ' Stream cipher

  ' Block cipher modes
  CRYPT_MODE_ECB                          ' ECB
  CRYPT_MODE_CBC                          ' CBC
  CRYPT_MODE_CFB                          ' CFB
  CRYPT_MODE_OFB                          ' OFB

  ' Public-key cipher modes
  CRYPT_MODE_PKC = 100                    ' PKC

  CRYPT_MODE_LAST                         ' Last possible crypt mode value

  ' In order that we can scan through a range of modes with
  '  cryptAlgoModeAvailable(), we define the following boundary points for
  '  the conventional encryption modes
  CRYPT_MODE_FIRST_CONVENTIONAL = CRYPT_MODE_STREAM
  CRYPT_MODE_LAST_CONVENTIONAL = CRYPT_MODE_PKC - 1
End Enum

' The encryption object types
Enum CRYPT_OBJECT_TYPE
  CRYPT_OBJECT_NONE                       ' No object type
  CRYPT_OBJECT_ENCRYPTED_KEY              ' Conventional-encrypted key
  CRYPT_OBJECT_PKCENCRYPTED_KEY           ' PKC-encrypted key
  CRYPT_OBJECT_SIGNATURE                  ' Signature
  CRYPT_OBJECT_LAST                       ' Last possible object type
End Enum

' The keyset types
Enum CRYPT_KEYSET_TYPE
  CRYPT_KEYSET_NONE                       ' No keyset type
  CRYPT_KEYSET_FILE                       ' Generic flat file keyset (PGP, X.509)
  CRYPT_KEYSET_LDAP                       ' LDAP directory service
  CRYPT_KEYSET_SMARTCARD                  ' Smart card key carrier
  CRYPT_KEYSET_ODBC                       ' Generic ODBC interface
  CRYPT_KEYSET_BSQL                       ' BSQL RDBMS
  CRYPT_KEYSET_MSQL                       ' mSQL RDBMS
  CRYPT_KEYSET_MYSQL                      ' MySQL RDBMS
  CRYPT_KEYSET_ORACLE                     ' Oracle RDBMS
  CRYPT_KEYSET_POSTGRES                   ' Postgres RDBMS
  CRYPT_KEYSET_RAIMA                      ' Raima Velocis RDBMS
  CRYPT_KEYSET_SOLID                      ' Solid RDBMS
  CRYPT_KEYSET_LAST                       ' Last possible keyset type
  CRYPT_FIRST_RDBMS = CRYPT_KEYSET_ODBC   ' Useful defines used internally for range checking
  CRYPT_LAST_RDBMS = CRYPT_KEYSET_LAST - 1
End Enum

' The key ID types
Enum CRYPT_KEYID_TYPE
  CRYPT_KEYID_NONE                        ' No key ID type
  CRYPT_KEYID_NAME                        ' Key owner name
  CRYPT_KEYID_EMAIL                       ' Key owner email address
  CRYPT_KEYID_OBJECT                      ' Encryption object which requires key
  CRYPT_KEYID_LAST                        ' Last possible key ID type
End Enum


' Data format types
Enum CRYPT_FORMAT_TYPE
  CRYPT_FORMAT_NONE                       ' No format type
  CRYPT_FORMAT_CRYPTLIB                   ' cryptlib native format
  CRYPT_FORMAT_SMIME                      ' PKCS #7 / S/MIME format
  CRYPT_FORMAT_PGP                        ' PGP format
  CRYPT_FORMAT_LAST                       ' Last possible format type
End Enum


' Encryption enveloping resource types
Enum CRYPT_RESOURCE_TYPE
  CRYPT_RESOURCE_NONE                     ' No resource type
  CRYPT_RESOURCE_SIGNATURE                ' Signature/signature check key
  CRYPT_RESOURCE_PASSWORD                 ' User password
  CRYPT_RESOURCE_KEY                      ' Conventional encryption key
  CRYPT_RESOURCE_PUBLICKEY                ' PKC encryption key
  CRYPT_RESOURCE_PRIVATEKEY               ' PKC decryption key
  CRYPT_RESOURCE_SESSIONKEY               ' Session key
  CRYPT_RESOURCE_HASH                     ' Hash algorithm
  CRYPT_RESOURCE_MAC                      ' MAC (usually a keyed hash function)
  CRYPT_RESOURCE_PADDING                  ' Message padding
  CRYPT_RESOURCE_COMPRESSION              ' Compression
  CRYPT_RESOURCE_LAST                     ' Last possible envelope key type
End Enum

' The keyset functions when a keyset resource is pushed into an envelope
Enum CRYPT_KEYFUNCTION_TYPE
  CRYPT_KEYFUNCTION_NONE                  ' No keyset function
  CRYPT_KEYFUNCTION_ENCRYPT               ' Public-key encryption
  CRYPT_KEYFUNCTION_DECRYPT               ' Private-key decryption
  CRYPT_KEYFUNCTION_SIGCHECK              ' Signature checking
  CRYPT_KEYFUNCTION_SIGNATURE             ' Signature generation
  CRYPT_KEYFUNCTION_LAST                  ' Last possible keyset function type
End Enum

'The certificate format type
Enum CRYPT_CERT_TYPE
  CRYPT_CERTTYPE_NONE                     ' No certificate type
  CRYPT_CERTTYPE_CERTIFICATE              ' Basic certificate
  CRYPT_CERTTYPE_CERTREQUEST              ' PKCS #10 certification request
  CRYPT_CERTTYPE_CRL                      ' CRL
  CRYPT_CERTTYPE_LAST                     ' Last possible cert.type
End Enum

' The certificate format type
Enum CRYPT_CERTFORMAT_TYPE
  CRYPT_CERTFORMAT_NONE                   ' No certificate format
  CRYPT_CERTFORMAT_BINARY                 ' Binary (DER) format
  CRYPT_CERTFORMAT_TEXT                   ' Text (base-64 encoded DER) format
  CRYPT_CERTFORMAT_LAST                   ' Last possible cert.format type
End Enum

' The certificate information types
Enum CRYPT_CERTINFO_TYPE
  CRYPT_CERTINFO_NONE                     ' No certificate information

  ' Pseudo-information which controls the way a certificate/CRL/cert
  ' request is processed
  CRYPT_CERTINFO_SELFSIGNED               ' Cert is self-signed
  CRYPT_CERTINFO_CURRENT_EXTENSION
  CRYPT_CERTINFO_CURRENT_FIELD
  CRYPT_CERTINFO_CURRENT_COMPONENT        ' Extension cursor management

  ' General certificate/CRL/cert request information
  CRYPT_CERTINFO_SERIALNUMBER             ' Serial number (read-only)
  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO     ' Public key
  CRYPT_CERTINFO_USERCERT                 ' User certificate
  CRYPT_CERTINFO_ISSUERNAME               ' Issuer DN (read-only)
  CRYPT_CERTINFO_VALIDFROM                ' Cert valid from time
  CRYPT_CERTINFO_VALIDTO                  ' Cert valid to time
  CRYPT_CERTINFO_SUBJECTNAME              ' Subject DN
  CRYPT_CERTINFO_ISSUERUNIQUEID           ' Issuer unique ID (read-only)
  CRYPT_CERTINFO_SUBJECTUNIQUEID          ' Subject unique ID (read-only)
  CRYPT_CERTINFO_CERTREQUEST              ' Cert.request (DN + public key)
  CRYPT_CERTINFO_THISUPDATE               ' CRL current update time
  CRYPT_CERTINFO_NEXTUPDATE               ' CRL next update time
  CRYPT_CERTINFO_REVOCATIONDATE           ' CRL cert revocation time

  ' X.520 Distinguished Name components
  CRYPT_CERTINFO_COUNTRYNAME = 50         ' countryName
  CRYPT_CERTINFO_STATEORPROVINCENAME      ' stateOrProvinceName
  CRYPT_CERTINFO_LOCALITYNAME             ' localityName
  CRYPT_CERTINFO_ORGANIZATIONNAME         ' organizationName
  CRYPT_CERTINFO_ORGANISATIONNAME = CRYPT_CERTINFO_ORGANIZATIONNAME
  CRYPT_CERTINFO_ORGANIZATIONALUNITNAME   ' organizationalUnitName
  CRYPT_CERTINFO_ORGANISATIONALUNITNAME = CRYPT_CERTINFO_ORGANIZATIONALUNITNAME
  CRYPT_CERTINFO_COMMONNAME               ' commonName

  ' X.509v3 certificate extensions.  There are a large number of possible
  '  extensions only the ones we care about are included here.  Some of
  '  the extensions have multiple fields for convenience we include the
  '  name of the entire extension so it can be referred to for operations
  '  where it's appropriate (for example it's possible to delete the entire
  '  basicConstraints extension with CRYPT_CERTINFO_BASICCONSTRAINTS
  '  instead of having to delete the individual fields seperately).

  '  Although it would be nicer to use names which match the extensions
  '  more closely (eg CRYPT_CERTINFO_BASICCONSTRAINTS_PATHLENCONSTRAINT)
  '  these exceed the 32-character ANSI minimum length for unique names
  '  and get really hairy once you get into the weird policy constraints
  '  extensions whose names wrap around the screen about three times.

  '  The following values are defined in OID order this isn't absolutely
  '  necessary but saves an extra layer of processing when encoding them

  ' 2 5 29 14 subjectKeyIdentifier
  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER = 100

  ' 2 5 29 15 keyUsage
  CRYPT_CERTINFO_KEYUSAGE

  ' 2 5 29 16 privateKeyUsagePeriod
  CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD
  CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE     ' notBefore
  CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER      ' notAfter

  ' 2 5 29 17 subjectAltName
  CRYPT_CERTINFO_SUBJECTALTNAME
  CRYPT_CERTINFO_SUBJECT_RFC822NAME       ' rfc822Name
  CRYPT_CERTINFO_EMAIL = CRYPT_CERTINFO_SUBJECT_RFC822NAME
  CRYPT_CERTINFO_SUBJECT_DNSNAME          ' dNSName
  CRYPT_CERTINFO_SUBJECT_DIRECTORYNAME    ' directoryName
  CRYPT_CERTINFO_SUBJECT_UNIFORMRESOURCEIDENTIFIER  ' uniformResourceIdentifier
  CRYPT_CERTINFO_SUBJECT_IPADDRESS        ' iPAddress
  CRYPT_CERTINFO_SUBJECT_REGISTEREDID     ' registeredID

  ' 2 5 29 18 issuerAltName
  CRYPT_CERTINFO_ISSUERALTNAME
  CRYPT_CERTINFO_ISSUER_RFC822NAME        ' rfc822Name
  CRYPT_CERTINFO_ISSUER_DNSNAME           ' dNSName
  CRYPT_CERTINFO_ISSUER_DIRECTORYNAME     ' directoryName
  CRYPT_CERTINFO_ISSUER_UNIFORMRESOURCEIDENTIFIER ' uniformResourceIdentifier
  CRYPT_CERTINFO_ISSUER_IPADDRESS         ' iPAddress
  CRYPT_CERTINFO_ISSUER_REGISTEREDID      ' registeredID

  ' 2 5 29 19 basicConstraints
  CRYPT_CERTINFO_BASICCONSTRAINTS
  CRYPT_CERTINFO_CA                       ' cA
  CRYPT_CERTINFO_PATHLENCONSTRAINT        ' pathLenConstraint

  ' 2 5 29 21 cRLReason
  CRYPT_CERTINFO_CRLREASON

  ' 2 5 29 30 nameConstraints
  CRYPT_CERTINFO_NAMECONSTRAINTS
  CRYPT_CERTINFO_PERMITTEDSUBTREES        ' permittedSubtrees
  CRYPT_CERTINFO_EXCLUDEDSUBTREES         ' excludedSubtrees

  ' 2 5 29 32 certificatePolicies
  CRYPT_CERTINFO_CERTIFICATEPOLICIES
  CRYPT_CERTINFO_CERTPOLICYID             ' policyInformation.policyIdentifier

  ' 2 5 29 35 authorityKeyIdentifier
  CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER
  CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER  ' keyIdentifier
  CRYPT_CERTINFO_AUTHORITY_CERTISSUER     ' authorityCertIssuer
  CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER ' authorityCertSerialNumber

  ' 2 5 29 37 extKeyUsage
  CRYPT_CERTINFO_EXTKEYUSAGE
  CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING  ' individualCodeSigning
  CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING  ' commercialCodeSigning
  CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING   ' certTrustListSigning
  CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING       ' timeStampSigning
  CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO      ' serverGatedCrypto
  CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM    ' encrypedFileSystem
  CRYPT_CERTINFO_EXTKEY_SERVERAUTH                ' serverAuth
  CRYPT_CERTINFO_EXTKEY_CLIENTAUTH                ' clientAuth
  CRYPT_CERTINFO_EXTKEY_CODESIGNING               ' codeSigning
  CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION           ' emailProtection
  CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM            ' ipsecEndSystem
  CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL               ' ipsecTunnel
  CRYPT_CERTINFO_EXTKEY_IPSECUSER                 ' ipsecUser
  CRYPT_CERTINFO_EXTKEY_TIMESTAMPING              ' timeStamping
  CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO      ' serverGatedCrypto

  ' 2 16 840 1 113730 1 x Netscape extensions
  CRYPT_CERTINFO_NS_CERTTYPE                      ' netscape-cert-type
  CRYPT_CERTINFO_NS_BASEURL                       ' netscape-base-url
  CRYPT_CERTINFO_NS_REVOCATIONURL                 ' netscape-revocation-url
  CRYPT_CERTINFO_NS_CAREVOCATIONURL               ' netscape-ca-revocation-url
  CRYPT_CERTINFO_NS_CERTRENEWALURL                ' netscape-cert-renewal-url
  CRYPT_CERTINFO_NS_CAPOLICYURL                   ' netscape-ca-policy-url
  CRYPT_CERTINFO_NS_SSLSERVERNAME                 ' netscape-ssl-server-name
  CRYPT_CERTINFO_NS_COMMENT                       ' netscape-comment

  ' 2 23 42 7 0 SET hashedRootKey
  CRYPT_CERTINFO_SET_HASHEDROOTKEY
  CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT            ' rootKeyThumbPrint

  ' 2 23 42 7 1 SET certificateType
  CRYPT_CERTINFO_SET_CERTIFICATETYPE

  ' 2 23 42 7 2 SET merchantData
  CRYPT_CERTINFO_SET_MERCHANTDATA
  CRYPT_CERTINFO_SET_MERID                        ' merID
  CRYPT_CERTINFO_SET_MERACQUIRERBIN               ' merAcquirerBIN
  CRYPT_CERTINFO_SET_MERCHANTLANGUAGE             ' merNames.language
  CRYPT_CERTINFO_SET_MERCHANTNAME                 ' merNames.name
  CRYPT_CERTINFO_SET_MERCHANTCITY                 ' merNames.city
  CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE        ' merNames.stateProvince
  CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE           ' merNames.postalCode
  CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME          ' merNames.countryName
  CRYPT_CERTINFO_SET_MERCOUNTRY                   ' merCountry
  CRYPT_CERTINFO_SET_MERAUTHFLAG                  ' merAuthFlag

  ' 2 23 42 7 3 SET certCardRequired
  CRYPT_CERTINFO_SET_CERTCARDREQUIRED

  ' 2 23 42 7 4 SET tunneling
  CRYPT_CERTINFO_SET_TUNNELING
  CRYPT_CERTINFO_SET_TUNNELINGFLAG                ' tunneling
  CRYPT_CERTINFO_SET_TUNNELINGALGID               ' tunnelingAlgID

  CRYPT_CERTINFO_LAST                             ' Last possible certificate info type

  ' Useful defines used internally for range checking
  CRYPT_FIRST_PSEUDOINFO = CRYPT_CERTINFO_SELFSIGNED
  CRYPT_LAST_PSEUDOINFO = CRYPT_CERTINFO_SERIALNUMBER - 1
  CRYPT_FIRST_DN = CRYPT_CERTINFO_COUNTRYNAME
  CRYPT_LAST_DN = CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER - 1
  CRYPT_FIRST_EXTENSION = CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER
  CRYPT_LAST_EXTENSION = CRYPT_CERTINFO_LAST - 1
End Enum

Enum CRYPT_CERTERROR_TYPE
  CRYPT_CERTERROR_NONE                    ' No certificate error
  CRYPT_CERTERROR_SIZE                    ' Item too small or large
  CRYPT_CERTERROR_VALUE                   ' Item value is invalid
  CRYPT_CERTERROR_CONSTRAINT              ' Constraint violation in item
  CRYPT_CERTERROR_ABSENT                  ' Required item missing
  CRYPT_CERTERROR_PRESENT                 ' Non-allowed item present
  CRYPT_CERTERROR_LAST                    ' Last possible cert.error
End Enum

' Configuration options
Enum CRYPT_OPTION_TYPE
  CRYPT_OPTION_NONE                       ' Non-option

  ' Encryption options
  CRYPT_OPTION_ENCR_ALGO                  ' Encryption algorithm
  CRYPT_OPTION_ENCR_MODE                  ' Encryption mode
  CRYPT_OPTION_ENCR_HASH                  ' Hash algorithm
  CRYPT_OPTION_ENCR_COOKIES               ' Whether to export key cookies

  ' PKC options
  CRYPT_OPTION_PKC_ALGO                   ' Public-key encryption algorithm
  CRYPT_OPTION_PKC_KEYSIZE                ' Public-key encryption key size

  ' Signature options
  CRYPT_OPTION_SIG_ALGO                   ' Signature algorithm
  CRYPT_OPTION_SIG_KEYSIZE                ' Signature keysize

  ' Keying options
  CRYPT_OPTION_KEYING_ALGO                ' Key processing algorithm
  CRYPT_OPTION_KEYING_ITERATIONS          ' Key processing iterations

  ' Certificate options
  CRYPT_OPTION_CERT_CREATEV3CERT          ' Whether to create X.509v3 certs
  CRYPT_OPTION_CERT_PKCS10ALT             ' Use alternative PKCS #10 encoding
  CRYPT_OPTION_CERT_CHECKENCODING         ' Check for valid ASN.1 encoding
  CRYPT_OPTION_CERT_FIXSTRINGS            ' Whether to fix encoding of strings
  CRYPT_OPTION_CERT_VALIDITY              ' Certificate validity period
  CRYPT_OPTION_CERT_UPDATEINTERVAL        ' CRL update interval
  CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING
  CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING  ' Enforce validity nesting on R/W
  CRYPT_OPTION_CERT_ENCODE_CRITICAL
  CRYPT_OPTION_CERT_DECODE_CRITICAL         ' Enforce critical flag in extensions

  ' Keyset options
  CRYPT_OPTION_KEYS_PUBLIC                  ' Default encryption PKC database
  CRYPT_OPTION_KEYS_PRIVATE                 ' Default decryption PKC database
  CRYPT_OPTION_KEYS_SIGCHECK                ' Default sig.check PKC database
  CRYPT_OPTION_KEYS_SIGNATURE               ' Default sig.generation PKC database

  ' PGP keyset options
  CRYPT_OPTION_KEYS_PGP_PUBLIC              ' PGP public keyring
  CRYPT_OPTION_KEYS_PGP_PRIVATE             ' PGP private keyring
  CRYPT_OPTION_KEYS_PGP_SIGCHECK            ' PGP signature check keyring
  CRYPT_OPTION_KEYS_PGP_SIGNATURE           ' PGP signature gen.keyring

  ' RDBMS keyset options
  CRYPT_OPTION_KEYS_DBMS_NAMETABLE          ' Name of key database table
  CRYPT_OPTION_KEYS_DBMS_NAMENAME           ' Name of key owner name column
  CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL          ' Name of key owner email column
  CRYPT_OPTION_KEYS_DBMS_NAMEDATE           ' Name of key expiry date column
  CRYPT_OPTION_KEYS_DBMS_NAMENAMEID         ' Name of key nameID column
  CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID       ' Name of key issuerID column
  CRYPT_OPTION_KEYS_DBMS_NAMEKEYID          ' Name of key keyID column
  CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA        ' Name of key data column

  ' Hardware options
  CRYPT_OPTION_HW_SERIALRNG                 ' Serial-based hardware RNG
  CRYPT_OPTION_HW_SERIALRNG_PARAMS          ' Serial RNG parameters
  CRYPT_OPTION_HW_SERIALRNG_ONLY            ' Only use serial RNG

  ' Miscellaneous options
  CRYPT_OPTION_MISC_FORCELOCK               ' Whether to force memory locking
  CRYPT_OPTION_MISC_ASYNCBIND               ' Whether to bind to drivers async'ly
  CRYPT_OPTION_MISC_ENVTYPE                 ' Envelope type
  CRYPT_OPTION_LAST                         ' Last config option
End Enum

' Options passed to cryptOpenKeyset() and cryptOpenKeysetEx()
Enum CRYPT_KEYOPT_TYPE
  CRYPT_KEYOPT_NONE                       ' No options
  CRYPT_KEYOPT_READONLY                   ' Open keyset in read-only mode
  CRYPT_KEYOPT_CREATE                     ' Create a new keyset
  CRYPT_KEYOPT_LAST                       ' Last possible key option type
End Enum

'***************************************************************************
'                                                                          *
'                                               Encryption Data Structures *
'                                                                          *
'***************************************************************************

' Results returned from the encryption capability query
'
Type CRYPT_QUERY_INFO
  ' The algorithm, encryption mode, and algorithm and mode names
  cryptAlgo As Long                       ' The encryption algorithm
  cryptMode As Long                       ' The encryption mode
  algoName As String                      ' The algorithm name
  modeName As String                      ' The mode name

  ' The algorithm parameters
  blockSize As Long                       ' The basic block size of the algorithm
  minKeySize As Long                      ' Minimum key size in bytes
  keySize As Long                         ' Recommended key size in bytes
  maxKeySize As Long                      ' Maximum key size in bytes
  minIVsize As Long                       ' Minimum IV size in bytes
  ivSize As Long                          ' Recommended IV size in bytes
  maxIVsize As Long                       ' Maximum IV size in bytes

  ' Miscellaneous information (only used by some algorithms)
  hashValue As String * CRYPT_MAX_HASHSIZE ' Hash algoriithm hash value
End Type

' Results returned from the encryption object query.  These provide
'  information on the objects created by cryptExportKey()/
'  cryptCreateSignature()
'
Type CRYPT_OBJECT_INFO
  ' The object type and size
  objectType As Long
  objectSize As Long                        ' The object size

  ' The encryption algorithm and mode
  cryptAlgo As Long                         ' The encryption algorithm
  cryptMode As Long                         ' The encryption mode

  ' The key derivation algorithm and iteration count for EncryptedKey objects
  keySetupAlgo As Long                      ' Key setup algorithm
  keySetupIterations As Long                ' Key setup iteration count

  ' The hash algorithm for Signature objects
  hashAlgo As Long                          ' Hash algorithm

  ' The algorithm-specific information for EncryptedKey objects.  The
  '  algorithm-specific information can be passed directly to
  '  cryptCreateContextEx() for any algorithm (even those which would
  '  normally use cryptCreateContext())
  '
  p_cryptContextExInfo As Long                    ' Algo-specific information
  contextInfo As String * 32                      ' Storage for algo-specific info
End Type

' Extra algorithm-specific information for the hash algorithms, stored
'  within a crypt context.  Set the parameter values to CRYPT_USE_DEFAULT
'  to use the default values for this algorithm
'
Type CRYPT_INFO_SHA
  isSHA As Long                        ' Whether to use SHA rather than SHA1
End Type

' Extra algorithm-specific information for the conventional encryption
'  algorithms, stored within a crypt context.  Set the parameter values to
'  CRYPT_USE_DEFAULT to use the default values for this algorithm
'
Type CRYPT_INFO_DES
  isDESX As Long                       ' Whether to use the DESX variant
End Type

Type CRYPT_INFO_RC5
  rounds As Long                       ' Number of encryption rounds
End Type

Type CRYPT_INFO_SAFER
  useSaferSK As Long                   ' Whether to use strengthened-key version
  rounds As Long                       ' Number of encryption rounds
End Type

' Key information for the public-key encryption algorithms.  These fields
'  are not accessed directly, but can be manipulated with the init/set/
'  destroyComponents() macros
'
Type CRYPT_PKCINFO_DH
  ' Status information
  endianness As Long                   ' Endianness of Long strings
  isPublicKey As Long                  ' Whether this is a public or private key

  ' Public components
  p As String * CRYPT_MAX_PKCSIZE      ' Prime
  pLen As Long                         ' Length of prime in bits
  g As String * CRYPT_MAX_PKCSIZE      ' Base
  gLen As Long                         ' Length of base in bits
End Type

Type CRYPT_PKCINFO_RSA
  ' Status information
  endianness As Long                   ' Endianness of Long strings
  isPublicKey As Long                  ' Whether this is a public or private key

  ' Public components
  n As String * CRYPT_MAX_PKCSIZE      ' Modulus
  nLen As Long                         ' Length of modulus in bits
  e As String * CRYPT_MAX_PKCSIZE      ' Public exponent
  eLen As Long                         ' Length of public exponent in bits

  ' Private components
  d As String * CRYPT_MAX_PKCSIZE      ' Private exponent
  dLen As Long                         ' Length of private exponent in bits
  p As String * CRYPT_MAX_PKCSIZE      ' Prime factor 1
  pLen As Long                         ' Length of prime factor 1 in bits
  q As String * CRYPT_MAX_PKCSIZE      ' Prime factor 2
  qLen As Long                         ' Length of prime factor 2 in bits
  u As String * CRYPT_MAX_PKCSIZE      ' Mult.inverse of q, mod p
  uLen As Long                         ' Length of private exponent in bits
  e1 As String * CRYPT_MAX_PKCSIZE     ' Private exponent 1 (PKCS)
  e1Len As Long                        ' Length of private exponent in bits
  e2 As String * CRYPT_MAX_PKCSIZE     ' Private exponent 2 (PKCS)
  e2Len As Long                        ' Length of private exponent in bits
End Type

Type CRYPT_PKCINFO_DSA
  ' Status information
  endianness As Long                   ' Endianness of Long strings
  isPublicKey As Long                  ' Whether this is a public or private key

  ' Public components
  p As String * CRYPT_MAX_PKCSIZE      ' Prime modulus
  pLen As Long                         ' Length of prime modulus in bits
  q As String * CRYPT_MAX_PKCSIZE      ' Prime divisor
  qLen As Long                         ' Length of prime divisor in bits
  g As String * CRYPT_MAX_PKCSIZE      ' h^( ( p - 1) / q) mod p
  gLen As Long                         ' Length of g in bits
  y As String * CRYPT_MAX_PKCSIZE      ' Public random Long
  yLen As Long                         ' Length of public Long in bits

  ' Private components
  x As String * CRYPT_MAX_PKCSIZE      ' Private random Long
  xLen As Long                         ' Length of private Long in bits
End Type

Type CRYPT_PKCINFO_ELGAMAL
  ' Status information
  endianness As Long                   ' Endianness of Long strings
  isPublicKey As Long                  ' Whether this is a public or private key

  ' Public components
  p As String * CRYPT_MAX_PKCSIZE      ' Prime modulus
  pLen As Long                         ' Length of prime modulus in bits
  g As String * CRYPT_MAX_PKCSIZE      ' Generator
  gLen As Long                         ' Length of g in bits
  y As String * CRYPT_MAX_PKCSIZE      ' Public random Long
  yLen As Long                         ' Length of public Long in bits

  ' Private components
  x As String * CRYPT_MAX_PKCSIZE      ' Private random Long
  xLen As Long                         ' Length of private Long in bits
End Type

Declare Function cryptAddCertComponentNumeric Lib "cl32.dll" (ByVal certificate As Long, ByVal certInfoType As Long, ByRef certInfo As Any) As Long
Declare Function cryptAddCertComponentString Lib "cl32.dll" (ByVal certificate As Long, ByVal certInfoType As Long, ByRef certInfo As Any, ByRef certInfoLength As Long) As Long
Declare Function cryptAddCertExtension Lib "cl32.dll" (ByVal certificate As Long, ByVal oid As String, ByVal criticalFlag As Long, ByVal extension As Any, ByVal extensionLength As Long) As Long
Declare Function cryptAddKeyset Lib "cl32.dll" (ByVal envelope As Long, ByVal keyset As Long, ByVal keyFunction As Long) As Long
Declare Function cryptAddPrivateKey Lib "cl32.dll" (ByVal keyset As Long, ByVal cryptContext As Long, ByRef password As Any) As Long
Declare Function cryptAddPublicKey Lib "cl32.dll" (ByVal keyset As Long, ByVal cryptContext As Long) As Long
Declare Function cryptAddRandom Lib "cl32.dll" (ByRef randomData As Any, ByVal randomDataLength As Long) As Long
Declare Function cryptAddResource Lib "cl32.dll" (ByVal envelope As Long, ByVal resource As Long, ByRef data As Byte) As Long
Declare Function cryptAlgoAvailable Lib "cl32.dll" (ByVal cryptAlgo As Long) As Long
Declare Function cryptAsyncAbort Lib "cl32.dll" (ByVal cryptContext As Long) As Long
Declare Function cryptAsyncQuery Lib "cl32.dll" (ByVal cryptContext As Long) As Long
Declare Function cryptCheckCert Lib "cl32.dll" (ByVal certificate As Long, ByVal sigCheckContext As Long) As Long
Declare Function cryptCheckSignature Lib "cl32.dll" (ByRef signature As Any, ByVal sigCheckKey As Long, ByVal hashContext As Long) As Long
Declare Function cryptClaimObject Lib "cl32.dll" (cryptObject As Long)
Declare Function cryptCreateCert Lib "cl32.dll" (ByRef certificate As Long, ByVal cryptContext As Long) As Long
Declare Function cryptCreateContectEx Lib "cl32.dll" (ByRef cryptContext As Long, ByVal cryptAlgo As Long, ByVal cryptMode As Long, ByRef cryptContextEx As Any) As Long
Declare Function cryptCreateContext Lib "cl32.dll" (ByRef cryptContext As Long, ByVal cryptAlgo As Long, ByVal cryptMode As Long) As Long
Declare Function cryptCreateDeenvelope Lib "cl32.dll" (ByRef envelope As Long) As Long
Declare Function cryptCreateDeenvelopeEx Lib "cl32.dll" (ByRef envelope As Long, ByVal envelopeType As Long, ByVal bufferSize As Long) As Long
Declare Function cryptCreateEnvelope Lib "cl32.dll" (ByRef envelope As Long) As Long
Declare Function cryptCreateEnvelopeEx Lib "cl32.dll" (ByRef envelope As Long, ByVal envelopeType As Long, ByVal bufferSize As Long) As Long
Declare Function cryptCreateSignature Lib "cl32.dll" (ByRef signature As Any, ByVal signatureLength As Long, ByVal signContext As Long, ByVal hashContext As Long) As Long
Declare Function cryptDecrypt Lib "cl32.dll" (ByVal cryptContext As Long, ByVal buffer As String, ByVal length As Long) As Long
Declare Function cryptDeleteCertComponent Lib "cl32.dll" (ByVal certificate As Long, ByVal certInfoType As Long) As Long
Declare Function cryptDeleteCertExtension Lib "cl32.dll" (ByVal certificate As Long, ByVal oid As String) As Long
Declare Function cryptDeleteKey Lib "cl32.dll" (ByVal keyset As Long, ByVal keyIDtype As Long, ByRef keyID As Any) As Long
Declare Function cryptDeriveKey Lib "cl32.dll" (ByVal cryptContex As Long, ByVal userKey As String, ByVal userKeyLength As Long) As Long
Declare Function cryptDeriveKeyEx Lib "cl32.dll" (ByVal cryptContext As Long, ByVal userKey As String, ByVal userKeyLength As Long, ByVal algorithm As Long, ByVal iterations As Long) As Long
Declare Function cryptDestroyCert Lib "cl32.dll" (ByVal certificate As Long) As Long
Declare Function cryptDestroyContext Lib "cl32.dll" (ByVal cryptContext As Long) As Long
Declare Function cryptDestroyEnvelope Lib "cl32.dll" (ByVal envelope As Long) As Long
Declare Function cryptDestroyObject Lib "cl32.dll" (cryptObject As Long) As Long
Declare Function cryptEncrypt Lib "cl32.dll" (ByVal cryptContext As Long, ByVal buffer As String, ByVal length As Long) As Long
Declare Function cryptEnd Lib "cl32.dll" () As Long
Declare Function cryptEnvelopeSize Lib "cl32.dll" (ByVal envelope As Long, ByRef size As Long) As Long
Declare Function cryptExportCert Lib "cl32.dll" (ByRef certObject As Any, ByVal certObjectLength As Long, ByVal certificate As Long) As Long
Declare Function cryptExportKey Lib "cl32.dll" (ByRef encryptedKey As Any, ByVal encryptedKeyLength As Long, ByVal exportKey As Long, ByVal sessionKeyContext As Long) As Long
Declare Function cryptGenerateKey Lib "cl32.dll" (ByVal cryptContext As Long) As Long
Declare Function cryptGenerateKeyAsync Lib "cl32.dll" (ByVal cryptContext As Long) As Long
Declare Function cryptGenerateKeyAsyncEx Lib "cl32.dll" (ByVal cryptContext As Long, ByVal keyLength As Long) As Long
Declare Function cryptGenerateKeyEx Lib "cl32.dll" (ByVal cryptContext As Long, ByVal keyLength As Long) As Long
Declare Function cryptGetCertComponentNumeric Lib "cl32.dll" (ByVal certificate As Long, ByVal certInfoType As Long, ByRef certInfo As Any) As Long
Declare Function cryptGetCertComponentString Lib "cl32.dll" (ByVal certificate As Long, ByVal certInfoType As Long, ByRef certInfo As Any, ByRef certInfoLength As Long) As Long
Declare Function cryptGetCertError Lib "cl32.dll" (ByVal cryptKey As Long, ByVal errorLocus, ByVal errorType As Long) As Long
Declare Function cryptGetCertExtension Lib "cl32.dll" (ByVal certificate As Long, ByVal oid As String, ByVal criticalFlag As Long, ByVal extension As Any, ByVal extensionLength As Long) As Long
Declare Function cryptGetFirstResource Lib "cl32.dll" (ByVal envelope As Long, ByVal resource As Long) As Long
Declare Function cryptGetKeysetError Lib "cl32.dll" (ByVal keyset As Long, ByVal errorCode As Long, ByVal errorString As String, ByVal errorStringLength As Long) As Long
Declare Function cryptGetNextResource Lib "cl32.dll" (ByVal envelope As Long, ByVal resource As Long) As Long
Declare Function cryptGetOptionNumeric Lib "cl32.dll" (ByVal cryptOption As Long, ByVal value As Long) As Long
Declare Function cryptGetOptionString Lib "cl32.dll" (ByVal cryptOption As Long, ByVal value As String, ByVal valueLength As Long) As Long
Declare Function cryptGetPrivateKey Lib "cl32.dll" (ByVal keyset As Long, ByVal cryptContext As Long, ByVal keyIDtype As Long, ByRef keyID As Any, ByRef password As Any) As Long
Declare Function cryptGetPublicKey Lib "cl32.dll" (ByVal keyset As Long, ByVal cryptContext As Long, ByVal keyIDtype As Long, ByRef keyID As Any) As Long
Declare Function cryptGetRandom Lib "cl32.dll" (ByRef randomData As Any, ByVal randomDataLength As Long) As Long
Declare Function cryptGetResourceOwnername Lib "cl32.dll" (ByVal envelope As Long, ByVal name As String) As Long
Declare Function cryptImportCert Lib "cl32.dll" (ByRef certObject As Any, ByVal certificate As Long) As Long
Declare Function cryptImportKey Lib "cl32.dll" (ByRef encryptedKey As Any, ByVal importKey As Long, ByVal sessionKeyContext As Long) As Long
Declare Function cryptInit Lib "cl32.dll" () As Long
Declare Function cryptInitEx Lib "cl32.dll" () As Long
Declare Function cryptKeySetClose Lib "cl32.dll" (ByVal keyset As Long) As Long
Declare Function cryptKeysetOpen Lib "cl32.dll" (ByVal keyset As Long, ByVal keysetType As Long, ByVal name As String, ByVal options As Long) As Long
Declare Function cryptKeysetOpenEx Lib "cl32.dll" (ByVal keyset As Long, ByVal keysetType As Long, ByVal name As String, ByVal param1 As String, ByVal param2 As String, ByVal param3 As String, ByVal options As Long) As Long
Declare Function cryptLoadIV Lib "cl32.dll" (ByVal cryptContext As Long, ByVal iv As Any, ByVal ivLength As Long) As Long
Declare Function cryptLoadKey Lib "cl32.dll" (ByVal cryptContext As Long, ByVal key As Any, ByVal keyLength As Long) As Long
Declare Function cryptModeAvailable Lib "cl32.dll" (ByVal cryptAlgo As Long, ByVal cryptMode As Long) As Long
' changed the ByVal's to ByRef's
Declare Function cryptPopData Lib "cl32.dll" (ByVal envelope As Long, ByRef buffer As Byte, ByVal length As Long, ByRef bytesCopied As Long) As Long
' changed the ByVal's to ByRef's
Declare Function cryptPushData Lib "cl32.dll" (ByVal envelope As Long, ByRef buffer As Byte, ByVal length As Long, ByRef bytesCopied As Long) As Long
Declare Function cryptQueryObject Lib "cl32.dll" (ByRef object As Any, ByRef cryptObjectInfo As CRYPT_OBJECT_INFO) As Long
Declare Function cryptReadOptions Lib "cl32.dll" () As Long
Declare Function cryptReleaseObject Lib "cl32.dll" (cryptObject As Long)
Declare Function cryptRetrieveIV Lib "cl32.dll" (ByVal cryptContext As Long, ByRef iv As Any) As Long
Declare Function cryptSetOptionNumeric Lib "cl32.dll" (ByVal cryptOption As Long, ByVal value As Long) As Long
Declare Function cryptSetOptionString Lib "cl32.dll" (ByVal cryptOption As Long, ByVal value As String) As Long
Declare Function cryptSignCert Lib "cl32.dll" (ByVal certificate As Long, ByVal signContext As Long) As Long
Declare Function cryptTransferObject Lib "cl32.dll" (cryptObject As Long, newOwnerID As Long) As Long
Declare Function cryptWriteOptions Lib "cl32.dll" () As Long

' Wrapper for DLL's cryptQueryContext and cryptQueryAlgoMode
'
' Internal Type expected by the DLL, since VB strings are very different
' from it's C counterparts
' This should only be used by the wrapper functions:
'   cryptQueryContext and cryptQueryAlgoMode
' to call cryptQueryContext_C and cryptQueryAlgoMode_C
' You should always use cryptQueryContext and cryptQueryAlgoMode along
' with CRYPT_QUERY_INFO
Type CRYPT_QUERY_INFO_C
  ' The algorithm, encryption mode, and algorithm and mode names
  cryptAlgo As Long                       ' The encryption algorithm
  cryptMode As Long                       ' The encryption mode
  algoName As Long                        ' The algorithm name
  modeName As Long                        ' The mode name

  ' The algorithm parameters
  blockSize As Long                       ' The basic block size of the algorithm
  minKeySize As Long                      ' Minimum key size in bytes
  keySize As Long                         ' Recommended key size in bytes
  maxKeySize As Long                      ' Maximum key size in bytes
  minIVsize As Long                       ' Minimum IV size in bytes
  ivSize As Long                          ' Recommended IV size in bytes
  maxIVsize As Long                       ' Maximum IV size in bytes

  ' Miscellaneous information (only used by some algorithms)
  hashValue As String * CRYPT_MAX_HASHSIZE ' Hash algoriithm hash value
End Type

' This are DLL functions to wrap
Declare Function cryptQueryAlgoMode_C Lib "cl32.dll" Alias "cryptQueryAlgoMode" (ByVal cryptAlgo As Long, ByVal cryptMode As Long, ByRef cryptQueryInfo As CRYPT_QUERY_INFO_C) As Long
Declare Function cryptQueryContext_C Lib "cl32.dll" Alias "cryptQueryContext" (ByVal cryptContext As Long, ByRef cryptQueryInfo As CRYPT_QUERY_INFO_C) As Long

' This will help in making the conversion from CRYPT_QUERY_INFO_C to
' CRYPT_QUERY_INFO
Declare Function crypt_lstrlen Lib "kernel32" Alias "lstrlen" (ByVal src As Any) As Long
Declare Function crypt_lstrcpy Lib "kernel32" Alias "lstrcpy" (ByVal dst As String, ByVal src As Any) As Long

' Macros to convert to and from the bit counts used for some encryption parameters
'
Public Function bitsToBytes(bits As Long) As Long
  bitsToBytes = (bits + 7) / 8
End Function

Public Function bytesToBits(bytes As Long) As Long
  bytesToBits = bytes * 8
End Function

' Macros to examine return values
'
Public Function cryptStatusError(status As Long) As Boolean
  cryptStatusError = ((status) < CRYPT_OK)
End Function

Public Function cryptStatusOK(status As Long) As Boolean
  cryptStatusOK = ((status) = CRYPT_OK)
End Function

' Macros to initialise and destroy the structure which stores the components of a public key
'
Public Sub cryptInitComponents(componentInfo As CRYPT_PKCINFO_RSA, componentEndianness As Long, componentKeyType As Long)
    With componentInfo
        .endianness = componentEndianness
        .isPublicKey = componentKeyType
        .n = String(CRYPT_MAX_PKCSIZE, 0)
        .nLen = 0
        .e = String(CRYPT_MAX_PKCSIZE, 0)
        .eLen = 0
        .d = String(CRYPT_MAX_PKCSIZE, 0)
        .dLen = 0
        .p = String(CRYPT_MAX_PKCSIZE, 0)
        .pLen = 0
        .q = String(CRYPT_MAX_PKCSIZE, 0)
        .qLen = 0
        .u = String(CRYPT_MAX_PKCSIZE, 0)
        .uLen = 0
        .e1 = String(CRYPT_MAX_PKCSIZE, 0)
        .e1Len = 0
        .e2 = String(CRYPT_MAX_PKCSIZE, 0)
        .e2Len = 0
    End With
End Sub

Public Sub cryptDestroyComponents(componentInfo As CRYPT_PKCINFO_RSA)
    With componentInfo
        .endianness = 0
        .isPublicKey = 0
        .n = String(CRYPT_MAX_PKCSIZE, 0)
        .nLen = 0
        .e = String(CRYPT_MAX_PKCSIZE, 0)
        .eLen = 0
        .d = String(CRYPT_MAX_PKCSIZE, 0)
        .dLen = 0
        .p = String(CRYPT_MAX_PKCSIZE, 0)
        .pLen = 0
        .q = String(CRYPT_MAX_PKCSIZE, 0)
        .qLen = 0
        .u = String(CRYPT_MAX_PKCSIZE, 0)
        .uLen = 0
        .e1 = String(CRYPT_MAX_PKCSIZE, 0)
        .e1Len = 0
        .e2 = String(CRYPT_MAX_PKCSIZE, 0)
        .e2Len = 0
    End With
End Sub

' Macros to set a component of a public key
'
Public Sub cryptSetComponent(destination, source, length As Long)
  If TypeName(destination) = "Long" Then destination = source
  If Left$(TypeName(destination), 6) = "String" Then destination = Left$(source, bitsToBytes(length))
End Sub


' Function to copy a pointed by address string to a real VB string
Private Function getStrFromPointer(ByVal Pointer As Long) As String
    Dim length As Long
    Dim str As String

    If Pointer = 0 Then
        getStrFromPointer = ""
        Exit Function
    End If
    length = crypt_lstrlen(Pointer)
    str = String(length + 1, " ")
    crypt_lstrcpy str, Pointer
    getStrFromPointer = Left(str, length)
End Function

' Wrapper for DLL's cryptQueryContext
'
Function cryptQueryContext(ByVal cryptContext As Long, ByRef cryptQueryInfo As CRYPT_QUERY_INFO) As Long
    Dim qi As CRYPT_QUERY_INFO_C
    Dim s As String, rc As Long

    rc = cryptQueryContext_C(cryptContext, qi)
    With cryptQueryInfo
        .algoName = getStrFromPointer(qi.algoName)
        .blockSize = qi.blockSize
        .cryptAlgo = qi.cryptAlgo
        .cryptMode = qi.cryptMode
        .hashValue = qi.hashValue
        .ivSize = qi.ivSize
        .keySize = qi.keySize
        .maxIVsize = qi.maxIVsize
        .maxKeySize = qi.maxKeySize
        .minIVsize = qi.minIVsize
        .minKeySize = qi.minKeySize
        .modeName = getStrFromPointer(qi.modeName)
    End With
    cryptQueryContext = rc
End Function

' Wrapper for DLL's cryptQueryAlgoMode
'
Function cryptQueryAlgoMode(ByVal cryptAlgo As Long, ByVal cryptMode As Long, ByRef cryptQueryInfo As CRYPT_QUERY_INFO) As Long
    Dim qi As CRYPT_QUERY_INFO_C
    Dim s As String, rc As Long

    rc = cryptQueryAlgoMode_C(cryptAlgo, cryptMode, qi)
    With cryptQueryInfo
        .algoName = getStrFromPointer(qi.algoName)
        .blockSize = qi.blockSize
        .cryptAlgo = qi.cryptAlgo
        .cryptMode = qi.cryptMode
        .hashValue = qi.hashValue
        .ivSize = qi.ivSize
        .keySize = qi.keySize
        .maxIVsize = qi.maxIVsize
        .maxKeySize = qi.maxKeySize
        .minIVsize = qi.minIVsize
        .minKeySize = qi.minKeySize
        .modeName = getStrFromPointer(qi.modeName)
    End With
    cryptQueryAlgoMode = rc
End Function


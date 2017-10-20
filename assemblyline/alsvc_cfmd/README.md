# CFMD Service

Performs hash lookups against Microsoft's [CleanFileMetaData](https://blogs.technet.microsoft.com/mmpc/2015/02/11/microsoft-steps-up-in-industry-efforts-on-mitigating-false-positives/) database.

**NOTE**: This service **requires** you to have access to Microsoft CFMD database. It is **not** preinstalled during a default installation

## Execution

This service works by querying Microsoft's CFMD database via direct database access to see whether the submitted file matches one originally compiled by Microsoft.

## Datasource

Because this service only uses the hash to query for information, by installing this service you also enable it as a datasource in the hash_search API (`/api/v3/hash_search/<HASH>/`)

## Access to Microsoft's CFMD Database

Access to Microsoft CFMD is restricted restricted to [Microsoft Security Response Center](https://technet.microsoft.com/en-us/library/dn440717.aspx) (MSRC) partners.
# NSRL Service

Performs hash lookups against NIST's [National Software Reference Library](http://www.nsrl.nist.gov/) database.

**NOTE**: This service **requires** you to download and install the NSRL database on a seperate server or VM. It is **not** preinstalled during a default installation

## Execution

This service works by querying the NSRL database via direct database access to see if the file that you are submitting was catalogued by the NIST as part of the National Software Reference Library.

## Datasource

Because this service only uses the hash to query for information, by installing this service you also enable it as a datasource in the hash_search API (`/api/v3/hash_search/<HASH>/`)

## Download/Installation of NSRL DB

You can download the NSRL hashset from the NIST website at [http://www.nsrl.nist.gov/Downloads.htm](http://www.nsrl.nist.gov/Downloads.htm).

After that, follow the [installation instructions](db/install_notes.md)

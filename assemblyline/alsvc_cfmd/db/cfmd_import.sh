#!/bin/bash

Exit() {
        echo $2 >&2
        exit $1
}

[ -z "$1" ] && Exit 1 "Usage: $0 <dir>"

echo -n "Mysql ROOT Password: "
read -s password
echo

echo -n "CFMD user password: "
read -s cfmdpassword
echo

echo "Dropping old cfmd DATABASE..."
mysql --local-infile -u root -p$password -e 'DROP DATABASE cfmd;'

echo "Creating cfmd DATABASE..."
mysql --local-infile -u root -p$password -e 'CREATE DATABASE cfmd;'

echo "Creating cfmd_hashes TABLE..."
mysql --local-infile -u root -p$password cfmd -e 'CREATE TABLE cfmd_hashes (md5 VARCHAR(32) NULL, sha1 VARCHAR(40) NULL, sha256 VARCHAR(64) NULL, size INT, filename TEXT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8;'

echo "Importing data:"
find $1 -name "cfmd*.xml" | while read file; do
        echo "  $file..."
        mysql --local-infile -u root -p$password cfmd -e "LOAD DATA LOCAL INFILE '$file' INTO TABLE cfmd_hashes CHARACTER SET 'utf8' LINES STARTING BY '<file' TERMINATED BY '</file>' (@tmp) SET md5 = LOWER(ExtractValue (@tmp, '//md5')), sha1 = LOWER(ExtractValue(@tmp, '//sha1')), sha256 = LOWER(ExtractValue(@tmp, '//sha256')), size = ExtractValue(@tmp, '//size'), filename = ExtractValue(@tmp, '//filename');"
done

echo "Indexing MD5s..."
mysql --local-infile -u root -p$password cfmd -e 'CREATE INDEX idx_md5 ON cfmd_hashes (md5) USING BTREE;'

echo "Indexing SHA1s..."
mysql --local-infile -u root -p$password cfmd -e 'CREATE INDEX idx_sha1 ON cfmd_hashes (sha1) USING BTREE;'

echo "Indexing SHA256s..."
mysql --local-infile -u root -p$password cfmd -e 'CREATE INDEX idx_sha256 ON cfmd_hashes (sha256) USING BTREE;'

echo "Creating CFMD user"
mysql --local-infile -u root -p$password cfmd -e "CREATE USER 'cfmd'@'%' IDENTIFIED BY '${cfmdpassword}';"
mysql --local-infile -u root -p$password cfmd -e "GRANT SELECT ON cfmd.* TO 'cfmd'@'%';"
mysql --local-infile -u root -p$password cfmd -e "FLUSH PRIVILEGES;"

echo "-- Done importing cfmd database --"
echo

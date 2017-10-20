#!/bin/sh

if [ $# -ne 1 ]; then
    echo "usage $0 <path-ending-in-version-number>" >&2
    exit 1
fi

Base=${1}

Version=`basename ${Base}`
File=${Base}/NSRLFile.txt
Manufacturer=${Base}/NSRLMfg.txt
OS=${Base}/NSRLOS.txt
Product=${Base}/NSRLProd.txt

psql -qt nsrl <<EOF
create table file_${Version} as select * from file_template where 0 = 1;
create table manufacturer_${Version} as
    select * from manufacturer_template where 0 = 1;
create table os_${Version} as select * from os_template where 0 = 1;
create table product_${Version} as select * from product_template where 0 = 1;
create or replace view file as select * from file_${Version};
create or replace view manufacturer as select * from manufacturer_${Version};
create or replace view os as select * from os_${Version};
create or replace view product as select * from product_${Version};
EOF

(cat <<EOF
copy file_${Version} from stdin csv;
EOF
tail -n +2 ${File} | iconv -f LATIN1) |
psql -qt nsrl

(cat <<EOF
copy manufacturer_${Version} from stdin csv;
EOF
tail -n +2 ${Manufacturer} | iconv -f LATIN1) |
psql -qt nsrl

(cat <<EOF
copy os_${Version} from stdin csv;
EOF
tail -n +2 ${OS} | iconv -f LATIN1) |
psql -qt nsrl

(cat <<EOF
copy product_${Version} from stdin csv;
EOF
tail -n +2 ${Product} | iconv -f LATIN1) |
psql -qt nsrl

psql -qt nsrl <<EOF
create index file_${Version}_md5 on file_${Version}(md5);
create index file_${Version}_sha1 on file_${Version}(sha1);
create index manufacturer_${Version}_code on manufacturer_${Version}(code);
create index os_${Version}_code on os_${Version}(code);
create index product_${Version}_code on product_${Version}(code);
EOF


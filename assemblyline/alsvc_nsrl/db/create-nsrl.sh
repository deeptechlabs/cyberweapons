#!/bin/sh

createdb nsrl

psql -qt nsrl <<EOF
create table file_template (
    sha1 text,
    md5 text,
    crc32 text,
    name text,
    size bigint,
    product_code integer,
    os_code text,
    special_code text
);

create table manufacturer_template (
    code text,
    name text
);

create table os_template (
    code text,
    name text,
    version text,
    manufacturer_code text
);

create table product_template (
    code integer,
    name text,
    version text,
    os_code text,
    manufacturer_code text,
    language text,
    application text
);

create or replace view file as select * from file_template;
create or replace view manufacturer as select * from manufacturer_template;
create or replace view os as select * from os_template;
create or replace view product as select * from product_template;

create or replace view nsrl as
select file.name as name,
       product.name as product,
       os.name as os,
       product.version as version,
       manufacturer.name as manufacturer,
       product.language as language,
       file.md5 as md5,
       file.sha1 as sha1,
       file.size as size
from file
inner join os on file.os_code = os.code
inner join product on file.product_code = product.code
inner join manufacturer on product.manufacturer_code = manufacturer.code;

create user ${1} with password "${2}";
grant select on nsrl to ${1};
EOF

#!/bin/sh -x

for bucket in file alert result error filescore submission
do
    cp /var/lib/riak/yz/${bucket}/conf/solrconfig.xml /var/lib/riak/yz/${bucket}/conf/solrconfig.xml.bak
    cp solrconfig.xml.${bucket} /var/lib/riak/yz/${bucket}/conf/solrconfig.xml
done



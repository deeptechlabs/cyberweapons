#!/bin/sh

# Example:
# cat ~/workspace/assemblyline/dispatcher*.out | ./graph.sh 6188e8e2-6c25-458f-9075-d15fc82158a7 >~/Desktop/graph.jpg

SID=$1; shift
if :; then
	echo 'digraph blah {'
	echo rankdir=LR
	grep -F ${SID} | grep -F Graph | sed -e 's/.*Graph://g'
	echo '}'
fi |
dot -Tsvg ${@}



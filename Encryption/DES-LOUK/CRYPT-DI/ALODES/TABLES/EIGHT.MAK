#!/usr/bin/perl

# This makes a $nb-bit bit-reverse-table

$nb = 8;
$upper = (1 << $nb);

for($i = 0; $i < $upper; $i++) {
    $k = 0;
    for($j = 0; $j < $nb; $j++) {
	$k |= (($i >> $j) & 01) << ($nb - 1 - $j);
    }
    printf "%04o,\n",$k;
}

# Local variables:
# mode: c
# tab-width: 8
# c-indent-level: 4
# end:

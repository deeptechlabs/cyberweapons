#!/usr/bin/perl

# This makes a $nb-bit bit-reverse-table

$nb = 7;
$upper = (1 << $nb);

for($i = 0; $i < $upper; $i++) {
    $x = $i;
    $k = 1;
    for($j = 0; $j < $nb; $j++) {
	$k ^= (($i >> $j) & 01);
    }
    $x ^= $k;
    printf "0x%02x, ",$x;
    if ($i % 8 == 7) {
	printf "\n";
    }
}

# Local variables:
# mode: c
# tab-width: 8
# c-indent-level: 4
# end:

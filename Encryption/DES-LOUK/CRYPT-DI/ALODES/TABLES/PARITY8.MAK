#!/usr/bin/perl

$nb = 8;
$upper = (1 << $nb);

for($i = 0; $i < $upper; $i += 2) {
    $x = $i;
    $k = 1;
    for($j = 0; $j < $nb; $j++) {
	$k ^= (($i >> $j) & 01);
    }
    $x ^= $k;
    printf "0x%02x, ",$x;
    if ($i % 16 == 14) {
	printf "\n";
    }
}

# Local variables:
# mode: c
# tab-width: 8
# c-indent-level: 4
# end:

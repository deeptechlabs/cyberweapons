#!/usr/bin/perl
# This makes combined S-box --> P-permutation --> E-permutation tables
# for each six-bit input data for each S-box.
#$| = 1;
for($i = 0; $i < 16; $i++) {
    $reverse4[$i] = ((($i & 0x08) >> 3) |
		    (($i & 0x04) >> 1) |
		    (($i & 0x02) << 1) |
		    (($i & 0x01) << 3));
}

$j = 0;
die "Cannot open S" until open(f,"S");
while (<f>) {
    @a = split(" ",$_);
    for($i = 0; $i < 16; $i++) {
	$x = shift(@a);
	$S[$j] = $x;
	$j++;
    }
}

$j = 0;
die "Cannot open P" until open(f,"P");
while (<f>) {
    @a = split(" ",$_);
    for($i = 0; $i < 4; $i++) {
	$x = shift(@a);
	$P[$j] = $x;
	$j++;
    }
}

$j = 0;
die "Cannot open E" until open(f,"E");
while (<f>) {
    @a = split(" ",$_);
    for($i = 0; $i < 6; $i++) {
	$x = shift(@a);
	$E[$j] = $x;
	$j++;
    }
}

$L[1024] = 0;
for($snum = 0; $snum < 8; $snum++) {
    for($i3 = 0; $i3 < 64; $i3++) {
	$i2 = ((($i3 & 0x01) << 5) |
	       (($i3 & 0x02) << 2) |
	       (($i3 & 0x04)     ) |
	       (($i3 & 0x08) >> 2) |
	       (($i3 & 0x10) >> 4) |
	       (($i3 & 0x20) >> 1));
	$i2 = $S[64 * $snum + $i2];
	$i2 = $reverse4[$i2];
	for($i = 0; $i < 48; $i++) {
	    $i4  = $P[$E[$i]-1]-1;
	    if (int($i4/4) == $snum && (($i2 >> ($i4 % 4)) & 01)) {
		$L[$snum * 128 + int($i / 24)*64 + $i3] |= (1 << ($i % 24));
		$aa = $L[$snum * 128 + int($i / 24)*64 + $i3];
	    }
	}
    }
    $i0 = $snum*128; $i1 = $i0+128;
    for($i = $i0; $i < $i1; $i++) {
	$x = $L[$i];
	$x = ((($x & 000000077)     ) |
	      (($x & 000007700) << 2) |
	      (($x & 000770000) << 4) |
	      (($x & 077000000) << 6));
	printf "0x%08x,\n",$x;
    }
}

# Local variables:
# mode: c
# tab-width: 8
# c-indent-level: 4
# end:

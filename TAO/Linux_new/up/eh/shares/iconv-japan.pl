#
# iconv-japan.pl - charset coversion for sjis<->jis, sjis<->euc,
#                  adopted from jcode.pl 2.13 written by
#                  Kazumasa Utashiro. <utashiro@iij.ad.jp>
#
# Since japan conversion in iconv() is incomplete, we use this instead
#
use strict;

my $re_jis0208  = '\e\$\@|\e\$B|\e&\@\e\$B';
my $re_jis0212  = '\e\$\(D';
my $re_jp       = "$re_jis0208|$re_jis0212";
my $re_asc      = '\e\([BJ]';
my $re_kana     = '\e\(I';

my $esc_0208    = "\e\$B";
my $esc_0212    = "\e\$(D";
my $esc_asc     = "\e(B";
my $esc_kana    = "\e(I";

my $re_sjis_c    = '[\201-\237\340-\374][\100-\176\200-\374]';
my $re_sjis_kana = '[\241-\337]';
my $re_euc_c     = '[\241-\376][\241-\376]';
my $re_euc_kana  = '\216[\241-\337]';
my $re_euc_0212  = '\217[\241-\376][\241-\376]';
my $undef_sjis   = "\x81\xac";

my %e2s=();
my %s2e=();

# SJIS to JIS
sub sjis2jis {
    my $s = shift;
    $$s =~ s/(($re_sjis_c|$re_sjis_kana)+)/_sjis2jis($1) . $esc_asc/geo;
}
sub _sjis2jis {
    my $s = shift;
    $s =~ s/(($re_sjis_c)+|($re_sjis_kana)+)/__sjis2jis($1)/geo;
    $s;
}
sub __sjis2jis {
    my $s = shift;
    if($s =~ /^$re_sjis_kana/o){
        $s =~ tr/\241-\337/\041-\137/;
        $esc_kana . $s;
    } else {
        $s =~ s/($re_sjis_c)/$s2e{$1} || s2e($1)/geo;
        $s =~ tr/\241-\376/\041-\176/;
        $esc_0208 . $s;
    }
}

# JIS to SJIS
sub jis2sjis {
    my $s = shift;
    $$s =~ s/($re_jp|$re_asc|$re_kana)([^\e]*)/_jis2sjis($1, $2)/geo;
}
sub _jis2sjis {
    my($esc, $s) = @_;
    if($esc =~ /^$re_jis0212/o){
        $s =~ s/../$undef_sjis/go;
    } elsif($esc !~ /^$re_asc/o){
        $s =~ tr/\041-\176/\241-\376/;
        if($esc =~ /^$re_jp/o){
            $s =~ s/($re_euc_c)/$e2s{$1} || e2s($1)/geo;
        }
    }
    $s;
}

# SJIS to EUC
sub sjis2euc {
    my $s = shift;
    $$s =~ s/($re_sjis_c|$re_sjis_kana)/$s2e{$1} || s2e($1)/geo;
}
sub s2e {
    my($c1, $c2, $code);
    ($c1, $c2) = unpack('CC', $code = shift);
    if(0xa1 <= $c1 && $c1 <= 0xdf){
        $c2 = $c1;
        $c1 = 0x8e;
    } elsif(0x9f <= $c2){
        $c1 = $c1 * 2 - ($c1 >= 0xe0 ? 0xe0 : 0x60);
        $c2 += 2;
    } else {
        $c1 = $c1 * 2 - ($c1 >= 0xe0 ? 0xe1 : 0x61);
        $c2 += 0x60 + ($c2 < 0x7f);
    }
    $s2e{$code} = pack('CC', $c1, $c2);
}

# EUC to SJIS
sub euc2sjis {
    my $s = shift;
    $$s =~ s/($re_euc_c|$re_euc_kana|$re_euc_0212)/$e2s{$1} || e2s($1)/geo;
}
sub e2s {
    my($c1, $c2, $code);
    ($c1, $c2) = unpack('CC', $code = shift);
    if($c1 == 0x8e){      # SS2
        return substr($code, 1, 1);
    } elsif($c1 == 0x8f){ # SS3
        return $undef_sjis;
    } elsif($c1 % 2){
        $c1 = ($c1>>1) + ($c1 < 0xdf ? 0x31 : 0x71);
        $c2 -= 0x60 + ($c2 < 0xe0);
    } else {
        $c1 = ($c1>>1) + ($c1 < 0xdf ? 0x30 : 0x70);
        $c2 -= 2;
    }
    $e2s{$code} = pack('CC', $c1, $c2);
}

1;

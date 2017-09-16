BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

use strict;

use Crypt::MD5;
use Crypt::SHA;
use Crypt::SHA0;
use Crypt::Blowfish;
use Crypt::DES;
use Crypt::DES3EDE;
use Crypt::IDEA;
use Crypt::CBC;
use Crypt::CFB;
use Crypt::ECB;


print "1..24\n";

my $md5_hash = Crypt::MD5->hash("ABC");
my $sha0_hash = Crypt::SHA0->hash("ABC");
my $sha_hash = Crypt::SHA->hash("abc");

print "1 ";
("$md5_hash" eq "MD5:902fbdd2b1df0c4f70b4a5d23525e932") || print "not ";
print "ok\n";

print "2 ";
("$sha0_hash" eq "SHA0:e6376bfcf102eab637c32689d6ae46e46437248d") || print "not ";
print "ok\n";

print "3 ";
("$sha_hash" eq "SHA:a9993e364706816aba3e25717850c26c9cd0d89d") || print "not ";
print "ok\n";

my $md = new Crypt::MD5;
$md->reset();
$md->add("ABC");

print "4 ";
($md5_hash == $md->digestAsHash()) || print "not ";
print "ok\n";


$md = new Crypt::SHA0;
$md->reset();
$md->add("ABC");

print "5 ";
($sha0_hash == $md->digestAsHash()) || print "not ";
print "ok\n";

######################################################################
# DES-ECB encrypt test
# 

my $key = pack("H*", "1234567812345678");
my $msg = "the quick brown fox jumps over the lazy dog12345";
my $block_cipher = new Crypt::DES $key;
my $cipher = new Crypt::ECB $block_cipher;

my $ciphertext = $cipher->encrypt($msg);
print "6 ";
($ciphertext eq pack("H*", "7ae76308d5f3f78d14c76ded78196fe0621e279065fe349b60128c8e4326e15ee8380e8520e845cb3e156c8d19db759a")) || print "not ";
print "ok\n";


######################################################################
# DES-ECB decrypt test
# 

print "7 ";
my $plaintext = $cipher->decrypt($ciphertext);
($plaintext eq "the quick brown fox jumps over the lazy dog12345") || print "not ";
print "ok\n";


######################################################################
# DES-CBC encrypt test
# 
my $init = pack("H*", "1234567812345678");
# dropped duplicate 'my' variables as later Perls warn.
$key = pack("H*", "1234567812345678");
$msg = "the quick brown fox jumps over the lazy dog";

$block_cipher = new Crypt::DES $key;
$cipher = new Crypt::CBC $block_cipher;

$ciphertext = $cipher->encrypt($init . $msg);

print "8 ";
($ciphertext eq pack("H*", "738189139e0b66e1f2f6a9f38b642c784b65460bbd028522e601c075b849d80c507b1579382b3b5a082cc2e34d3427f8f4283f3085270305")) || print "not ";
print "ok\n";

print "9 ";
$plaintext = $cipher->decrypt($ciphertext);
$plaintext = substr($plaintext, length($init), length($msg));	# Remove IV and trailer
($plaintext eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";

$block_cipher = new Crypt::DES $key;
$cipher = new Crypt::CFB $block_cipher;

$ciphertext = $cipher->encrypt($init . $msg);

print "10 ";
($ciphertext eq pack("H*", "7d859ec74f2fecf395ccc524911df6996c7985ce844af22307a855158e654e9b5eafa70c6c6e47ffabc574482222f5bfe39964")) || print "not ";
print "ok\n";

print "11 ";
$cipher->reset();
$plaintext = $cipher->decrypt($ciphertext);
substr($plaintext, 0, length($init)) = '';	# Remove IV
($plaintext eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";

######################################################################
# IDEA-ECB encrypt test
# 

$key = pack("H*", "12345678123456781234567812345678");
$msg = "the quick brown fox jumps over the lazy dog12345";
$block_cipher = new Crypt::IDEA $key;
$cipher = new Crypt::ECB $block_cipher;

$ciphertext = $cipher->encrypt($msg);
print "12 ";
($ciphertext eq pack("H*", "36a3fa0501c7467eb29116a74b1bf5a48f6d67fb55ca7f713012b2b812d32979c2d87eab35350a0b1c614ce5802354b0")) || print "not ";
print "ok\n";


######################################################################
# IDEA-ECB decrypt test
# 

print "13 ";
$plaintext = $cipher->decrypt($ciphertext);
($plaintext eq "the quick brown fox jumps over the lazy dog12345") || print "not ";
print "ok\n";


$key = pack("H*", "12345678123456781234567812345678");
$block_cipher = new Crypt::IDEA $key;
$cipher = new Crypt::CBC $block_cipher;
$msg = "the quick brown fox jumps over the lazy dog";

$ciphertext = $cipher->encrypt($init . $msg);

print "14 ";
($ciphertext eq pack("H*", "1dd4f67ff04a9a2068b993fdd6781bee5d848160f905fdceb5cd67921a4457845417d4d0ff68ae6399770358887974b0467c834b5b2d8aaf")) || print "not ";
print "ok\n";

print "15 ";
$plaintext = $cipher->decrypt($ciphertext);
$plaintext = substr($plaintext, length($init), length($msg));	# Remove IV and trailer
($plaintext eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";

$block_cipher = new Crypt::IDEA $key;
$cipher = new Crypt::CFB $block_cipher;

$ciphertext = $cipher->encrypt($init . $msg);

print "16 ";
($ciphertext eq pack("H*", "4fe7f788e9e98b22b3dc9a7ffa37e416192d9d166b3f1a6316c6e03a4fba781dda9b2146c7b804158b2c2197b3a78bc7a4f1dd")) || print "not ";
print "ok\n";

print "17 ";
$cipher->reset();
$plaintext = $cipher->decrypt($ciphertext);
substr($plaintext, 0, length($init)) = '';	# Remove IV
($plaintext eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";

######################################################################
# Blowfish-ECB encrypt test
# 

$key = pack("H*", "12345678123456781234567812345678");
$msg = "the quick brown fox jumps over the lazy dog12345";
$block_cipher = new Crypt::Blowfish $key;
$cipher = new Crypt::ECB $block_cipher;

$ciphertext = $cipher->encrypt($msg);
print "18 ";
($ciphertext eq pack("H*", "0359437e761d03da74e216b360985a91f8e177e561f1da170ea122ffaa4f17b7b59116369ec5d3a935c4406c11c69334")) || print "not ";
print "ok\n";


######################################################################
# Blowfish-ECB decrypt test
# 

print "19 ";
$plaintext = $cipher->decrypt($ciphertext);
($plaintext eq "the quick brown fox jumps over the lazy dog12345") || print "not ";
print "ok\n";






$block_cipher = new Crypt::Blowfish $key;
$cipher = new Crypt::CFB $block_cipher;

$msg = "the quick brown fox jumps over the lazy dog";
$ciphertext = $cipher->encrypt($init . $msg);

print "20 ";
($ciphertext eq pack("H*", "59c2044d75682701f5156c38a6b36d289bb864f60348a94a096b3f056bb1a170f6ea27168d4ffdfb81877f79f4a7172400a71c")) || print "not ";
print "ok\n";

print "21 ";
$cipher->reset();
$plaintext = $cipher->decrypt($ciphertext);
substr($plaintext, 0, length($init)) = '';	# Remove IV
($plaintext eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";


$key = pack("H*", "123456781234567812345678123456781234567812345678");
$block_cipher = new Crypt::DES3EDE $key;
$cipher = new Crypt::CFB $block_cipher;

$ciphertext = $cipher->encrypt($init . $msg);

print "22 ";
($ciphertext eq pack("H*", "7d859ec74f2fecf395ccc524911df6996c7985ce844af22307a855158e654e9b5eafa70c6c6e47ffabc574482222f5bfe39964")) || print "not ";
print "ok\n";

print "23 ";
$cipher->reset();
$plaintext = $cipher->decrypt($ciphertext);
substr($plaintext, 0, length($init)) = '';	# Remove IV
($plaintext eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";

print "24 ";
$cipher->reset();
my $plaintext2 = $cipher->decrypt(substr($ciphertext, 0, 13));
$plaintext2 .= $cipher->decrypt(substr($ciphertext, 13));
substr($plaintext2, 0, length($init)) = '';	# Remove IV
($plaintext2 eq "the quick brown fox jumps over the lazy dog") || print "not ";
print "ok\n";

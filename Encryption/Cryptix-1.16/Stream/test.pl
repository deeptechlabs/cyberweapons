BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

package TestObj;

use Stream::Streamable;
@ISA = qw(Streamable);


sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	$dos->write($self->{'data'});
	$dos->writeByte($self->{'byte'});
	$dos->writeInt16($self->{'int16'});
	$dos->writeInt16($self->{'uint16'});
	$dos->writeInt32($self->{'int32'});
	$dos->writeInt32($self->{'uint32'});
	$dos->writeFloat($self->{'float'});
	$dos->writeDouble($self->{'double'});
	$dos->writeTime($self->{'time'});
	$dos->writeString($self->{'string'});
	$dos->writeLength($self->{'len1'});
	$dos->writeLength($self->{'len2'});
	$dos->writeLength($self->{'len3'});
	$dos->writeLength($self->{'len4'});
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	$self->{'data'} = $dis->read(8);
	$self->{'byte'} = $dis->readByte();
	$self->{'int16'} = $dis->readInt16();
	$self->{'uint16'} = $dis->readUnsignedInt16();
	$self->{'int32'} = $dis->readInt32();
	$self->{'uint32'} = $dis->readUnsignedInt32();
	$self->{'float'} = $dis->readFloat();
	$self->{'double'} = $dis->readDouble();
	$self->{'time'} = $dis->readTime();
	$self->{'string'} = $dis->readString();
	$self->{'len1'} = $dis->readLength();
	$self->{'len2'} = $dis->readLength();
	$self->{'len3'} = $dis->readLength();
	$self->{'len4'} = $dis->readLength();

	defined ($self->{'data'}) || return "read data failed";
	defined ($self->{'byte'}) || return "read byte failed";
	defined ($self->{'int16'}) || return "read int16 failed";
	defined ($self->{'uint16'}) || return "read uint16 failed";
	defined ($self->{'int32'}) || return "read int32 failed";
	defined ($self->{'uint32'}) || return "read uint32 failed";
	defined ($self->{'float'}) || return "read float failed";
	defined ($self->{'double'}) || return "read double failed";
	defined ($self->{'time'}) || return "read time failed";
	defined ($self->{'string'}) || return "read string failed";
	defined ($self->{'len1'}) || return "read len1 failed";
	defined ($self->{'len2'}) || return "read len2 failed";
	defined ($self->{'len3'}) || return "read len3 failed";
	defined ($self->{'len4'}) || return "read len4 failed";

	$self;
}



package main;

use Stream::IO;
use POSIX;
use Carp;


my $sos = new Stream::StringOutput;
my $dos = new Stream::DataOutput $sos;

$dos->write("Testing!");
$dos->writeByte(42);
$dos->writeInt16(1234);
$dos->writeInt16(32768);
$dos->writeInt32(987654);
$dos->writeInt32(2147483648);
$dos->writeFloat(1.25);
$dos->writeDouble(3.14159262536);
$dos->writeTime(1);
$dos->writeString("Hello world\n");
$dos->writeLength(0);
$dos->writeLength(100);
$dos->writeLength(10000);
$dos->writeLength(1000000);

# print unpack("H*", $sos->data()), "\n";

print "1..23\n";

print "1 ok\n" if (unpack("H*", $sos->data()) eq "54657374696e67212a04d28000000f1206800000003fa00000400921fb507a3535000000010c48656c6c6f20776f726c640a0064ce10bd8440");

my $sis = new Stream::StringInput $sos->data();
my $dis = new Stream::DataInput $sis;

print "2 ok\n" if ($dis->read(8) eq "Testing!");
print "3 ok\n" if ($dis->readByte() == 42);
print "4 ok\n" if ($dis->readInt16() == 1234);
print "5 ok\n" if ($dis->readUnsignedInt16() == 32768);
print "6 ok\n" if ($dis->readInt32() == 987654);
print "7 ok\n" if ($dis->readUnsignedInt32() == 2147483648);
print "8 ok\n" if ($dis->readFloat() == 1.25);
print "9 ok\n" if ($dis->readDouble() == 3.14159262536);
print "10 ok\n" if ($dis->readTime() == 1);
print "11 ok\n" if ($dis->readString() eq "Hello world\n");
print "12 ok\n" if ($dis->readLength() == 0);
print "13 ok\n" if ($dis->readLength() == 100);
print "14 ok\n" if ($dis->readLength() == 10000);
print "15 ok\n" if ($dis->readLength() == 1000000);

my $obj = restore TestObj $sos->data();
if (ref($obj))
{
	print "16 ok\n"
}
else
{
	print "16 not ok\n";
	croak("Restore failed - $obj");
}

print "17 ok\n" if ($obj->save() eq $sos->data());

my $tmpfile = POSIX::tmpnam();

my $fos = new Stream::FileOutput $tmpfile;
$dos = new Stream::DataOutput $fos;

$obj->saveToDataStream($dos);

$fos->close(); # Ensure data has been saved

my $fis = new Stream::FileInput $tmpfile;
ref($fis) || croak("Failed to open $tmpfile - $fis");

if ($fis->readAll() eq $obj->save())
{
	print "18 ok\n";
}
else
{
	print "18 not ok\n";
}

$fis->seek(0, 0);

$dis = new Stream::DataInput $fis;
ref($dis) || croak("Failed to create Stream::DataInput - $dis");

my $obj2 = restoreFromDataStream TestObj $dis;
if (ref($obj2))
{
	print "19 ok\n"
}
else
{
	croak("Restore failed - $obj2");
}

print "20 ok\n" if ($obj->save() eq $obj2->save());

unlink($tmpfile);	# Remove unwanted file


$tmpfile = POSIX::tmpnam();

$obj2->saveToFile($tmpfile);
my $obj3 = restoreFromFile TestObj $tmpfile;

print "21 ok\n" if ($obj2->save() eq $obj3->save());

unlink($tmpfile);	# Remove unwanted file


#
#	Test string <-> array functions
#
my $arr = ["Hello", "World"];
my $arrstr = Stream::DataEncoding::encodeArray($arr);
my $decarr = Stream::DataEncoding::decodeArray($arrstr);
ref $decarr || die "Error - $decarr";
if ((@$decarr == 2) && (ref $decarr) && ($$decarr[0] eq "Hello") && ($$decarr[1] eq "World"))
{
	print "22 ok\n";
}
else
{
	print "22 not ok\n";
}


#
#	Test empty array in string <-> array functions
#
$arr = ["", "0"];
$arrstr = Stream::DataEncoding::encodeArray($arr);
$decarr = Stream::DataEncoding::decodeArray($arrstr);
ref $decarr || die "Error - $decarr";
if ((@$decarr == 2) && (ref $decarr) && ($$decarr[0] eq "") && ($$decarr[1] eq "0"))
{
	print "23 ok\n";
}
else
{
	print "23 not ok\n";
}

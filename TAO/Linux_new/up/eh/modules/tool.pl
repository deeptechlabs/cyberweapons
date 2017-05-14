package ow::tool;
use strict;
#
# tool.pl - routines independent with openwebmail systems
#

use Digest::MD5 qw(md5);
use Carp;
$Carp::MaxArgNums = 0; # return all args in Carp output

sub findbin {
   my $name=$_[0];
   foreach ('/usr/local/bin', '/usr/bin', '/bin', '/usr/X11R6/bin/', '/opt/bin') {
      return "$_/$name" if ( -x "$_/$name");
   }
   return;
}

sub find_configfile {
   my @configfiles=@_;
   my $cgi_bin = $INC[$#INC];		# get cgi-bin/openwebmail path from @INC
   foreach (@configfiles) {
      if (m!^/!) {			# absolute path
         return($_) if (-f $_);
      } else {
         return("$cgi_bin/$_") if (-f "$cgi_bin/$_");
      }
   }
   return ('');
}

sub load_configfile {	
   my ($configfile, $r_config)=@_;

   open(CONFIG, $configfile) or return(-1, $!);

   my ($line, $key, $value, $blockmode);
   $blockmode=0;
   while (($line=<CONFIG>)) {
      chomp $line;
      $line=~s/\s+$//;
      if ($blockmode) {
         if ( $line =~ m!</$key>! ) {
            $blockmode=0;
            ${$r_config}{$key}=untaint($value);
         } else {
            $value .= "$line\n";
         }
      } else {
         $line=~s/\s*#.*$//;
         $line=~s/^\s+//;
         next if ($line eq '');
         if ( $line =~ m!^<\s*(\S+)\s*>$! ) {
            $blockmode=1;
            $key=$1; $value='';
         } elsif ( $line =~ m!(\S+)\s+(.+)! ) {
            ${$r_config}{$1}=untaint($2);
         }
      }
   }
   close(CONFIG);
   if ($blockmode) {
      return(-2, "unclosed $key block");
   }

   return 0;
}

# use 'require' to load the package ow::$file
# then alias ow::$file::symbo to $newpkg::symbo
# through Glob and 'tricky' symbolic reference feature
sub loadmodule {
   my ($newpkg, $moduledir, $modulefile, @symlist)=@_;
   $modulefile=~s|/||g; $modulefile=~s|\.\.||g; # remove / and .. to anti path hack

   # this would be done only once because of %INC
   my $modulepath=ow::tool::untaint("$moduledir/$modulefile");
   require $modulepath;

   # . - is not allowed for package name
   my $modulepkg='ow::'.$modulefile; $modulepkg=~s/\.pl//; $modulepkg=~s/[\.\-]/_/g;

   # release strict refs until block end
   no strict 'refs';
   # use symbo table of package $modulepkg if no symbo passed in
   @symlist=keys %{$modulepkg.'::'} if ($#symlist<0);

   foreach my $sym (@symlist) {
      # alias symbo of sub routine into current package
      *{$newpkg.'::'.$sym}=*{$modulepkg.'::'.$sym};
   }

   return;
}

sub hostname {
   my $hostname=`/bin/hostname`; chomp ($hostname);
   return($hostname) if ($hostname=~/\./);

   my $domain="unknow";
   open (R, "/etc/resolv.conf");
   while (<R>) {
      chomp;
      if (/domain\s+\.?(.*)/i) {$domain=$1;last;}
   }
   close(R);
   return("$hostname.$domain");
}

sub clientip {
   my $clientip;
   if (defined($ENV{'HTTP_CLIENT_IP'})) {
      $clientip=$ENV{'HTTP_CLIENT_IP'};
   } elsif (defined($ENV{'HTTP_X_FORWARDED_FOR'}) &&
            $ENV{'HTTP_X_FORWARDED_FOR'} !~ /^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.0\.)/ ) {
      $clientip=(split(/,/,$ENV{'HTTP_X_FORWARDED_FOR'}))[0];
   } else {
      $clientip=$ENV{'REMOTE_ADDR'}||"127.0.0.1";
   }
   return $clientip;
}

use vars qw(%_has_module_err);
sub has_module {
   my $module=$_[0];
   return 1 if (defined($INC{$module}));
   return 0 if ($_has_module_err{$module});
   eval { require $module; };	# test module existance and load if it exists
   if ($@) {
      $_has_module_err{$module}=1; return 0;
   } else {
      return 1;
   }
}

# return a string composed by the modify time & size of a file
sub metainfo {
   return '' if (!-e $_[0]);
   # dev, ino, mode, nlink, uid, gid, rdev, size, atime, mtime, ctime, blksize, blocks
   my @a=stat($_[0]);
   return("mtime=$a[9] size=$a[7]");
}

# generate a unique (well nearly) checksum through MD5
sub calc_checksum {
   my $checksum = md5(${$_[0]});
   # remove any \n so it doesn't react with ow folder db index delimiter
   $checksum =~ s/[\r\n]/./sg;
   return $checksum;
}

# escape & unescape routine are not available in CGI.pm 3.0
# so we borrow the 2 routines from 2.xx version of CGI.pm
sub unescapeURL {
    my $todecode = shift;
    return undef if (!defined($todecode));
    $todecode =~ tr/+/ /;       # pluses become spaces
    $todecode =~ s/%([0-9a-fA-F]{2})/pack("c",hex($1))/ge;
    return $todecode;
}

sub escapeURL {
    my $toencode = shift;
    return undef if (!defined($toencode));
    $toencode=~s/([^a-zA-Z0-9_.-])/uc sprintf("%%%02x",ord($1))/eg;
    return $toencode;
}

# generate html code for hidden options, faster than the one in CGI.pm
# limitation: no escape for keyname, value can not be an array
sub hiddens {
   my %h=@_;
   my ($temphtml, $key);
   foreach my $key (sort keys %h) {
      $temphtml.=qq|<INPUT TYPE="hidden" NAME="$key" VALUE="$h{$key}">\n|;
   }
   return $temphtml;
}

# big5: hi 81-FE, lo 40-7E A1-FE, range a440-C67E C940-F9D5 F9D6-F9FE
# gbk : hi 81-FE, lo 40-7E 80-FE, range hi*lo
sub zh_dospath2fname {
   my ($dospath, $newdelim)=@_;
   my $buff='';
   while ( 1 ) {
      # this line can't be put inside while or will go wrong in perl 5.8.0
      if ($dospath=~m!([\x81-\xFE][\x40-\x7E\x80-\xFE]|.)!g) {
         if ($1 eq '\\') {
            if ($newdelim ne '') {
               $buff.=$newdelim;
            } else {
               $buff='';
            }
         } else {
            $buff.=$1;
         }
      } else {
         last;
      }
   }
   return $buff;
}

sub ext2contenttype {
   my $ext=lc($_[0]); $ext=~s/^.*\.//;	# remove part before .

   return("text/plain")			if ($ext =~ /^(?:asc|te?xt|cc?|h|cpp|asm|pas|f77|lst|sh|pl)$/);
   return("text/html")			if ($ext =~ /^html?$/);
   return("text/xml")			if ($ext =~ /^(?:xml|xsl)$/);
   return("text/richtext")		if ($ext eq "rtx");
   return("text/sgml")			if ($ext =~ /^sgml?$/);
   return("text/vnd.wap.wml")		if ($ext eq "wml");
   return("text/vnd.wap.wmlscript")	if ($ext eq "wmls");
   return("text/$1")			if ($ext =~ /^(?:css|rtf)$/);

   return("model/vrml")			if ($ext =~ /^(?:wrl|vrml)$/);

   return("image/jpeg")			if ($ext =~ /^(?:jpg|jpe|jpeg)$/);
   return("image/$1")			if ($ext =~ /^(bmp|gif|ief|png|psp)$/);
   return("image/tiff")			if ($ext =~ /^tiff?$/);
   return("image/x-xbitmap")		if ($ext eq "xbm");
   return("image/x-xpixmap")		if ($ext eq "xpm");
   return("image/x-cmu-raster")		if ($ext eq "ras");
   return("image/x-portable-anymap")	if ($ext eq "pnm");
   return("image/x-portable-bitmap")	if ($ext eq "pbm");
   return("image/x-portable-grayma")	if ($ext eq "pgm");
   return("image/x-portable-pixmap")	if ($ext eq "ppm");
   return("image/x-rgb")		if ($ext eq "rgb");

   return("video/mpeg")			if ($ext =~ /^(?:mpeg?|mpg|mp2)$/);
   return("video/x-msvideo")		if ($ext =~ /^(?:avi|dl|fli)$/);
   return("video/quicktime")		if ($ext =~ /^(?:mov|qt)$/);

   return("audio/x-wav")		if ($ext eq "wav");
   return("audio/mpeg")			if ($ext =~ /^(?:mp[23]|mpga)$/);
   return("audio/midi")			if ($ext =~ /^(?:midi?|kar)$/);
   return("audio/x-realaudio")		if ($ext eq "ra");
   return("audio/basic")		if ($ext =~ /^(?:au|snd)$/);
   return("audio/x-mpegurl")		if ($ext eq "m3u");
   return("audio/x-aiff")		if ($ext =~ /^aif[fc]?$/);
   return("audio/x-pn-realaudio")	if ($ext =~ /^ra?m$/);

   return("application/msword") 	if ($ext eq "doc");
   return("application/x-mspowerpoint") if ($ext eq "ppt");
   return("application/x-msexcel") 	if ($ext eq "xls");
   return("application/x-msvisio")	if ($ext eq "visio");

   return("application/postscript")	if ($ext =~ /^(?:ps|eps|ai)$/);
   return("application/mac-binhex40")	if ($ext eq "hqx");
   return("application/xhtml+xml")	if ($ext =~ /^(?:xhtml|xht)$/);
   return("application/x-javascript")	if ($ext eq "js");
   return("application/x-httpd-php")	if ($ext =~ /^php[34]?$/);
   return("application/x-vcard")	if ($ext eq "vcf");
   return("application/x-shockwave-flash") if ($ext eq "swf");
   return("application/x-texinfo")	if ($ext =~ /^(?:texinfo|texi)$/);
   return("application/x-troff")	if ($ext =~ /^(?:tr|roff)$/);
   return("application/x-troff-$1")     if ($ext =~ /^(man|me|ms)$/);
   return("application/x-$1")		if ($ext =~ /^(dvi|latex|shar|tar|tcl|tex)$/);
   return("application/ms-tnef")        if ($ext =~ /^tnef$/);
   return("application/$1")		if ($ext =~ /^(pdf|zip)$/);

   return("application/octet-stream");
}

sub contenttype2ext {
   my $contenttype=$_[0];
   my ($class, $ext, $dummy)=split(/[\/\s;,]+/, $contenttype);

   return("txt")  if ($contenttype eq "N/A");
   return("mp3")  if ($contenttype=~m!audio/mpeg!i);
   return("au")   if ($contenttype=~m!audio/x\-sun!i);
   return("ra")   if ($contenttype=~m!audio/x\-realaudio!i);

   $ext=~s/^x-//i;
   return(lc($ext))  if length($ext) <=4;

   return("txt")  if ($class =~ /text/i);
   return("msg")  if ($class =~ /message/i);

   return("doc")  if ($ext =~ /msword/i);
   return("ppt")  if ($ext =~ /powerpoint/i);
   return("xls")  if ($ext =~ /excel/i);
   return("vsd")  if ($ext =~ /visio/i);
   return("vcf")  if ($ext =~ /vcard/i);
   return("tar")  if ($ext =~ /tar/i);
   return("zip")  if ($ext =~ /zip/i);
   return("avi")  if ($ext =~ /msvideo/i);
   return("mov")  if ($ext =~ /quicktime/i);
   return("swf")  if ($ext =~ /shockwave\-flash/i);
   return("hqx")  if ($ext =~ /mac\-binhex40/i);
   return("ps")   if ($ext =~ /postscript/i);
   return("js")   if ($ext =~ /javascript/i);
   return("tnef") if ($ext =~ /ms\-tnef/i);
   return("bin");
}

sub email2nameaddr {	# name, addr are guarentee to not null
   my ($name, $address)=_email2nameaddr($_[0]);
   if ($name eq "") {
      $name=$address; $name=~s/\@.*$//;
      $name=$address if (length($name)<=2);
   }
   return($name, $address);
}

sub _email2nameaddr {	# name may be null
   my $email=$_[0];
   my ($name, $address);

   if ($email =~ m/^\s*"?<?(.+?)>?"?\s*<(.*)>$/) {
      $name = $1; $address = $2;
   } elsif ($email =~ m/<?(.*?@.*?)>?\s+\((.+?)\)/) {
      $name = $2; $address = $1;
   } elsif ($email =~ m/<(.+)>/) {
      $name = ""; $address = $1;
   } elsif ($email =~ m/(.+)/) {
      $name = "" ; $address = $1;
   }
   $name=~s/^\s+//; $name=~s/\s+$//;
   $address=~s/^\s+//; $address=~s/\s+$//;
   return($name, $address);
}

sub str2list {
   my ($str, $keepnull)=@_;
   my (@list, @tmp, $delimiter, $prevchar, $postchar);

   if ($str=~/,/) {
      @tmp=split(/,/, $str);
      $delimiter=',';
   } elsif ($str=~/;/) {
      @tmp=split(/;/, $str);
      $delimiter=';';
   } else {
      return($str);
   }

   my $pairmode=0;
   foreach my $token (@tmp) {
      next if ($token=~/^\s*$/ && !$keepnull);
      if ($pairmode) {
         push(@list, pop(@list).$delimiter.$token);
         $pairmode=0 if ($token=~/\Q$postchar\E/ && $token!~/\Q$prevchar\E.*\Q$postchar\E/);
      } else {
         push(@list, $token);
         if ($token=~/^.*?(['"\(])/) {
            $prevchar=$postchar=$1;
            $postchar=')' if ($prevchar eq '(' );
            $pairmode=1 if ($token!~/\Q$prevchar\E.*\Q$postchar\E/);
         }
      }
   }

   foreach (@list) {
      s/^\s+//; s/\s+$//;
   }
   return(@list);
}

sub untaint {
   local $_ = shift;	# this line makes param into a new variable. don't remove it.
   m/^(.*)$/s;
   return $1;
}

sub is_tainted {
   return ! eval { join('',@_), kill 0; 1; };
}

sub is_regex {
   return eval { m!$_[0]!; 1; };
}

sub stacktrace {
   return Carp::longmess(join(' ', @_));
}

# for profiling and debugging
sub log_time {
   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
   my ($today, $time);

   ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =localtime;
   $today=sprintf("%4d%02d%02d", $year+1900, $mon+1, $mday);
   $time=sprintf("%02d%02d%02d",$hour,$min, $sec);

   open(Z, ">> /tmp/openwebmail.debug");

   # unbuffer mode
   select(Z); local $| = 1;
   select(STDOUT);

   print Z "$today $time ", join(" ",@_), "\n";	# @_ contains msgs to log
   close(Z);
   chmod(0666, "/tmp/openwebmail.debug");
}

# dump data stru with its reference for debugging
sub dumpref {
   my ($var, $c)=@_;
   return("too many levels") if ($c>128);
   my $type=ref($var);
   my $prefix=' 'x$c;
   my $output="$type\n";
   if ($type =~/SCALAR/) {
      $output.=$prefix.refdump(${$var}, $c)."\n";
   } elsif ($type=~/HASH/) {
      foreach my $key (sort keys %{$var}) {
         $output.=$prefix." "."$key =>".refdump(${$var}{$key}, length("$key =>")+$c+1)."\n";
      }
   } elsif ($type=~/ARRAY/) {
      foreach my $member (@{$var}) {
         $output.=$prefix." ".refdump($member, $c+1)."\n";
      }
   } else {
      return("$var (untaint)") if (!is_tainted($_[0]));
      return($var);
   }
   $output=~s/\n\n+/\n/sg;
   return $output;
}

1;

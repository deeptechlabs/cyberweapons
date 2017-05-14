#
# iconv.pl - do charset conversion with system iconv() support
#
# It requires Text::Iconv perl module (Text-Iconv-1.2.tar.gz)
#
use strict;
use Text::Iconv;
require "shares/iconv-chinese.pl";
require "shares/iconv-japan.pl";

use vars qw(%charset_convlist %charset_localname %localname_cache);

# mapping www charset to all possible iconv charset on various platform
%charset_localname=
   (
   'big5'          => [ 'BIG5', 'zh_TW-big5' ],
   'euc-jp'        => [ 'EUC-JP', 'EUC', 'eucJP' ],
   'euc-kr'        => [ 'EUC-KR', 'EUCKR' ],
   'gb2312'        => [ 'GB2312', 'gb2312' ],
   'gbk'           => [ 'GBK', 'gbk' ],
   'iso-2022-jp'   => [ 'ISO-2022-JP', 'JIS' ],
   'iso-2022-kr'   => [ 'ISO-2022-KR' ],
   'iso-8859-1'    => [ 'ISO-8859-1', '8859-1', 'ISO8859-1', 'ISO_8859-1' ],
   'iso-8859-2'    => [ 'ISO-8859-2', '8859-2', 'ISO8859-2', 'ISO_8859-2' ],
   'iso-8859-5'    => [ 'ISO-8859-5', '8859-5', 'ISO8859-5', 'ISO_8859-5' ],
   'iso-8859-6'    => [ 'ISO-8859-6', '8859-6', 'ISO8859-6', 'ISO_8859-6' ],
   'iso-8859-7'    => [ 'ISO-8859-7', '8859-7', 'ISO8859-7', 'ISO_8859-7' ],
   'iso-8859-8'    => [ 'ISO-8859-9', '8559-8', 'ISO8859-8', 'ISO_8859-8' ],
   'iso-8859-9'    => [ 'ISO-8859-9', '8859-9', 'ISO8859-9', 'ISO_8859-9' ],
   'iso-8859-13'   => [ 'ISO-8859-13', '8859-13', 'ISO8859-13', 'ISO_8859-13' ],
   'koi8-r'        => [ 'KOI8-R' ],
   'koi8-u'        => [ 'KOI8-U' ],
   'ksc5601'       => [ 'KSC5601' ],
   'ks_c_5601-1987'=> [ 'KSC5601' ],
   'shift_jis'     => [ 'SJIS', 'SHIFT_JIS', 'SHIFT-JIS' ],
   'tis-620'       => [ 'TIS-620', 'TIS620' ],
   'utf-8'         => [ 'UTF-8', 'UTF8' ],
   'windows-1250'  => [ 'WINDOWS-1250', 'CP1250' ],
   'windows-1251'  => [ 'WINDOWS-1251', 'CP1251' ],
   'windows-1252'  => [ 'WINDOWS-1252', 'CP1252' ],
   'windows-1253'  => [ 'WINDOWS-1253', 'CP1253' ],
   'windows-1254'  => [ 'WINDOWS-1254', 'CP1254' ],
   'windows-1255'  => [ 'WINDOWS-1255', 'CP1255' ],
   'windows-1256'  => [ 'WINDOWS-1256', 'CP1256' ],
   'windows-1257'  => [ 'WINDOWS-1257', 'CP1257' ],
   );

# convertable list of WWW charset, the definition is:
# charset in the left can be converted from the charsets in right list
%charset_convlist=
   (
   'big5'          => [ 'utf-8', 'gb2312', 'gbk' ],
   'euc-jp'        => [ 'utf-8', 'iso-2022-jp', 'shift_jis' ],
   'euc-kr'        => [ 'utf-8', 'ks_c_5601-1987', 'ksc5601', 'iso-2022-kr' ],
   'iso-2022-kr'   => [ 'utf-8', 'ks_c_5601-1987', 'ksc5601', 'euc-kr' ],
   'ks_c_5601-1987'=> [ 'utf-8', 'euc-kr', 'iso-2022-kr' ],
   'ksc5601'       => [ 'utf-8', 'euc-kr', 'iso-2022-kr' ],
   'gb2312'        => [ 'utf-8', 'big5', 'gbk' ],
   'gbk'           => [ 'utf-8', 'big5', 'gb2312' ],
   'iso-2022-jp'   => [ 'utf-8', 'shift_jis', 'euc-jp' ],
   'iso-8859-1'    => [ 'utf-8', 'windows-1252' ],
   'iso-8859-2'    => [ 'utf-8', 'windows-1250' ],
   'iso-8859-5'    => [ 'utf-8', 'winodws-1251', 'koi8-r' ],
   'iso-8859-6'    => [ 'utf-8', 'winodws-1256' ],
   'iso-8859-7'    => [ 'utf-8', 'winodws-1253' ],
   'iso-8859-8'    => [ 'utf-8', 'winodws-1255' ],
   'iso-8859-9'    => [ 'utf-8', 'windows-1254' ],
   'iso-8859-13'   => [ 'utf-8', 'windows-1257' ],
   'koi8-r'        => [ 'utf-8', 'windows-1251', 'iso-8859-5' ],
   'koi8-u'        => [ 'utf-8' ],
   'shift_jis'     => [ 'utf-8', 'iso-2022-jp', 'euc-jp' ],
   'tis-620'       => [ 'utf-8' ],
   'windows-1250'  => [ 'utf-8', 'iso-8859-2' ],
   'windows-1251'  => [ 'utf-8', 'koi8-r', 'iso-8859-5' ],
   'windows-1252'  => [ 'utf-8', 'iso-8859-1' ],
   'windows-1253'  => [ 'utf-8', 'iso-8859-7' ],
   'windows-1254'  => [ 'utf-8', 'iso-8859-9' ],
   'windows-1255'  => [ 'utf-8', 'iso-8859-8' ],
   'windows-1256'  => [ 'utf-8', 'iso-8859-6' ],
   'windows-1257'  => [ 'utf-8', 'iso-8859-13' ],
   'utf-8'         => [ 'big5', 'euc-jp', 'euc-kr', 'gb2312', 'gbk',
			'iso-2022-jp', 'iso-2022-kr',
			'iso-8859-1', 'iso-8859-2', 'iso-8859-5', 'iso-8859-6',
			'iso-8859-7', 'iso-8859-9', 'iso-8859-13',
			'koi8-r', 'koi8-u', 'ksc5601', 'ks_c_5601-1987',
			'shift_jis', 'tis-620',
			'windows-1250', 'windows-1251', 'windows-1252',
			'windows-1253', 'windows-1254', 'windows-1255',
			'windows-1256', 'windows-1257' ]
   );

sub is_convertable {
   my ($from, $to)=@_;
   $from=lc($from); $to=lc($to);

   return 1 if ($from eq 'big5' && ($to eq 'gb2312'||$to eq 'gbk'));
   return 1 if (($from eq 'gb2312'||$from eq 'gbk') && $to eq 'big5');
   return 1 if ($from eq 'shift_jis' && $to eq 'iso-2022-jp');
   return 1 if ($from eq 'iso-2022-jp' && $to eq 'shift_jis');
   return 1 if ($from eq 'shift_jis' && $to eq 'euc-jp');
   return 1 if ($from eq 'euc-jp' && $to eq 'shift_jis');

   return 0 if ( !defined($charset_convlist{$to}) );
   foreach my $charset (@{$charset_convlist{$to}}) {
      if ($from=~/$charset/) {
         my $converter=iconv_open($charset, $to);
         return 0 if (! $converter);
         $converter='';
         return 1;
      }
   }
   return 0;
}

%localname_cache=();
sub iconv_open {
   my ($from, $to)=@_;

   if (defined($localname_cache{$from}) &&
       defined($localname_cache{$to}) ) {
      return(Text::Iconv->new($localname_cache{$from}, $localname_cache{$to}));
   }

   my $converter;
   foreach my $localfrom (@{$charset_localname{$from}}) {
      foreach my $localto (@{$charset_localname{$to}}) {
         eval { $converter = Text::Iconv->new($localfrom, $localto); };
         next if ($@);
         $localname_cache{$from}=$localfrom;
         $localname_cache{$to}=$localto;
       	 return($converter);
      }
   }
   return('');
}

sub iconv {
   my ($from, $to, @text)=@_;
   $from=lc($from); $to=lc($to);

   my $converter = iconv_open($from, $to);
   my @result;

   for (my $i=0; $i<=$#text; $i++) {
      if ($text[$i]!~/[^\s]/) {
         $result[$i]=$text[$i]; next;
      }
      # try convertion routine in iconv-chinese, iconv-japan first
      if ($from  eq 'big5' && ($to eq 'gb2312'||$to eq 'gbk') ) {
         $result[$i]=b2g($text[$i]); next;
      } elsif (($from eq 'gb2312'||$from eq 'gbk') && $to eq 'big5' ) {
         $result[$i]=g2b($text[$i]); next;
      } elsif ($from eq 'shift_jis' && $to eq 'iso-2022-jp' ) {
         $result[$i]=$text[$i]; sjis2jis(\$result[$i]); next;
      } elsif ($from eq 'iso-2022-jp' && $to eq 'shift_jis' ) {
         $result[$i]=$text[$i]; jis2sjis(\$result[$i]); next;
      } elsif ($from eq 'shift_jis' && $to eq 'euc-jp' ) {
         $result[$i]=$text[$i]; sjis2euc(\$result[$i]); next;
      } elsif ($from eq 'euc-jp' && $to eq 'shift_jis' ) {
         $result[$i]=$text[$i]; euc2sjis(\$result[$i]); next;
      }
      if ($converter) {
         my @line=split(/\n/, $text[$i]);
         for (my $j=0; $j<=$#line; $j++) {
            next if ($line[$j]=~/^\s*$/);
            my $converted=$converter->convert($line[$j]);
            if ($converted ne '') {
               $line[$j]=$converted;
            } else {
               # add [charset?] at the beginning if covert failed
               $line[$j]="[".uc($from)."?]".$line[$j];
               $converter='';	# free mem?
               $converter = iconv_open($from, $to);
            }
         }
         $result[$i]=join("\n", @line);
      } else {
         $result[$i]=$text[$i];
      }
   }
   $converter='';
   return (@result);
}

1;

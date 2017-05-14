package ow::lang;
use strict;
#
# language.pl - language tables and routines
#
use strict;
use vars qw(%languagenames %languagecharsets %httpaccept2language %RTL);

# The language name for each language abbreviation
%languagenames = (
   'ar.CP1256'    => 'Arabic - Windows',
   'ar.ISO8859-6' => 'Arabic - ISO 8859-6',
   'bg'           => 'Bulgarian',
   'ca'           => 'Catalan',
   'cs'           => 'Czech',
   'da'           => 'Danish',
   'de'           => 'Deutsch',			# German
   'el'           => 'Hellenic',			# Hellenic/Greek
   'en'           => 'English',
   'es'           => 'Spanish',			# Espanol
   'fi'           => 'Finnish',
   'fr'           => 'French',
   'he.ISO8859-8' => 'Hebrew - ISO 8859-8',
   'he.CP1255'    => 'Hebrew - Windows',
   'hu'           => 'Hungarian',
   'id'           => 'Indonesian',
   'it'           => 'Italiano',
   'ja_JP.eucJP'     => 'Japanese - eucJP',
   'ja_JP.Shift_JIS' => 'Japanese - ShiftJIS',
   'kr'           => 'Korean',
   'lt'           => 'Lithuanian',
   'nl'           => 'Nederlands',
   'no'           => 'Norwegian',
   'pl'           => 'Polish',
   'pt'           => 'Portuguese',
   'pt_BR'        => 'Portuguese Brazil',
   'ro'           => 'Romanian',
   'ru'           => 'Russian',
   'sk'           => 'Slovak',
   'sr'           => 'Serbian',
   'sv'           => 'Swedish',			# Svenska
   'th'           => 'Thai',
   'tr'           => 'Turkish',
   'uk'           => 'Ukrainian',
   'ur'           => 'Urdu',
   'zh_CN.GB2312' => 'Chinese - Simplified',
   'zh_TW.Big5'   => 'Chinese - Traditional '
);

# the language charset for each language abbreviation
%languagecharsets =(
   'ar.CP1256'    => 'windows-1256',
   'ar.ISO8859-6' => 'iso-8859-6',
   'bg'           => 'windows-1251',
   'ca'           => 'iso-8859-1',
   'cs'           => 'iso-8859-2',
   'da'           => 'iso-8859-1',
   'de'           => 'iso-8859-1',
   'en'           => 'iso-8859-1',
   'el'           => 'iso-8859-7',
   'es'           => 'iso-8859-1',
   'fi'           => 'iso-8859-1',
   'fr'           => 'iso-8859-1',
   'he.CP1255'    => 'windows-1255',
   'he.ISO8859-8' => 'iso-8859-8',
   'hu'           => 'iso-8859-2',
   'id'           => 'iso-8859-1',
   'it'           => 'iso-8859-1',
   'ja_JP.eucJP'     => 'euc-jp',
   'ja_JP.Shift_JIS' => 'shift_jis',
   'kr'           => 'euc-kr',
   'lt'           => 'windows-1257',
   'nl'           => 'iso-8859-1',
   'no'           => 'iso-8859-1',
   'pl'           => 'iso-8859-2',
   'pt'           => 'iso-8859-1',
   'pt_BR'        => 'iso-8859-1',
   'ro'           => 'iso-8859-2',
   'ru'           => 'koi8-r',
   'sk'           => 'iso-8859-2',
   'sr'           => 'iso-8859-2',
   'sv'           => 'iso-8859-1',
   'th'           => 'tis-620',
   'tr'           => 'iso-8859-9',
   'uk'           => 'koi8-u',
   'ur'           => 'utf-8',
   'zh_CN.GB2312' => 'gb2312',
   'zh_TW.Big5'   => 'big5',
   'utf-8'        => 'utf-8'		# charset only, use en lang/template
);

# Right-to-Left language table, used to siwtch direct of arrow
%RTL = (
   'ar.CP1256'    => 1,		# arabic
   'ar.ISO8859-6' => 1,
   'he.CP1255'    => 1,		# hebrew
   'he.ISO8859-8' => 1,
   'ur'           => 1		# urdu
);

# HTTP_ACCEPT_LANGUAGE to owm lang
%httpaccept2language =(
   'ar'    => 'ar.CP1256',
   'he'    => 'he.CP1255',
   'iw'    => 'he.ISO8859-8',
   'in'    => 'id',
   'ja'    => 'ja_JP.Shift_JIS',
   'ko'    => 'kr',
   'pt-br' => 'pt_BR',
   'zh'    => 'zh_CN.GB2312',
   'zh-cn' => 'zh_CN.GB2312',
   'zh-sg' => 'zh_CN.GB2312',
   'zh-tw' => 'zh_TW.Big5',
   'zh-hk' => 'zh_TW.Big5'
);

########## GUESS_LANGUAGE ########################################
sub guess_language {
   my @lang;
   foreach ( split(/[,;\s]+/, lc($ENV{'HTTP_ACCEPT_LANGUAGE'})) ) {
      push(@lang, $_) if (/^[a-z\-_]+$/);
      push(@lang, $1) if (/^([a-z]+)\-[a-z]+$/ ); # eg: zh-tw -> zh
   }
   foreach my $lang (@lang) {
      return $lang                       if (defined($languagenames{$lang}));
      return $httpaccept2language{$lang} if (defined($httpaccept2language{$lang}));
   }
   return('en');
}
########## END GUESS_LANGUAGE ####################################

1;

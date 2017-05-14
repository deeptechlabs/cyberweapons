package ow::mailparse;
use strict;
#
# mailparse.pl - mail parser with mime multiple decoding
#
# 1. it parse mail recursively.
# 2. it converts uuencoded blocks into baed64-encoded attachments
#
# Note: These parse_... routine are designed for CGI program !
#       if (searchidid eq "") {
#          # html display / content search mode
#          only attachment contenttype of text/... or n/a will be returned
#       } elsif (searchid eq "all") {
#          # used in message forwarding
#          all attachments are returned
#       } elsif (searchid eq specific-id ) {
#          # html requesting an attachment with specific nodeid
#          only return attachment with the id
#       }

use MIME::Base64;
use MIME::QuotedPrint;
require "modules/tool.pl";
require "modules/mime.pl";

sub parse_header {
   # concatenate folding lines in header but not the last blank line
   my $header=${$_[0]}; $header=~s/\s+$//s; $header=~s/\s*\n\s+/ /sg; 
   my $r_message=$_[1];

   my @lines=split(/\r*\n/, $header);
   ${$r_message}{delimiter}=shift(@lines) if ($lines[0]=~/^From /);
   foreach (@lines) {
      last if (! /(.+?):\s*(.*)/);
      next if ($1 eq 'Received');
      ${$r_message}{lc($1)}=$2;
   }
   return;
}

# Handle "message/rfc822,multipart,uuencode inside message/rfc822" encapsulation
sub parse_rfc822block {
   my ($r_block, $nodeid, $searchid)=@_;
   my @attachments=();
   my ($headerlen, $header, $body, %msg);

   $nodeid=0 unless defined $nodeid;
   $headerlen=index(${$r_block},  "\n\n");
   $header=substr(${$r_block}, 0, $headerlen);

   $msg{'content-type'}='N/A';	# assume msg as simple text
   parse_header(\$header, \%msg);

   # recover incomplete header for msgs resent from mailing list, tricky!
   if ($msg{'content-type'} eq 'N/A') {
      my $testdata=substr(${$r_block}, $headerlen+2, 256);
      if (($testdata=~/multi\-part message in MIME format/i &&
           $testdata=~/\n--(\S*?)\n/s) ||
          $testdata=~/\n--(\S*?)\nContent\-/is ||
          $testdata=~/^--(\S*?)\nContent\-/is ) {
         $msg{'content-type'}=qq|multipart/mixed; boundary="$1"|;
      }
   }

   if ($msg{'content-type'} =~ /^multipart/i) {
      my ($subtype, $boundary, $boundarylen);
      my ($bodystart, $boundarystart, $nextboundarystart, $attblockstart);
      my $search_html_related_att=0;

      $subtype = $msg{'content-type'};
      $subtype =~ s/^multipart\/(.*?)[;\s].*$/$1/i;

      $boundary = $msg{'content-type'};
      $boundary =~ s/.*?boundary\s?=\s?"([^"]+)".*$/$1/i or
         $boundary =~ s/.*?boundary\s?=\s?([^\s;]+);?\s?.*$/$1/i;
      $boundary="--$boundary";
      $boundarylen=length($boundary);

      $bodystart=$headerlen+2;
      $boundarystart=index(${$r_block}, $boundary, $bodystart);
      if ($boundarystart >= $bodystart) {
          $body=substr(${$r_block}, $bodystart, $boundarystart-$bodystart);
      } else {
          $body=substr(${$r_block}, $bodystart);
          return($header, $body, \@attachments);
      }

      my $i=0;
      $attblockstart=$boundarystart+$boundarylen;
      while ( substr(${$r_block}, $attblockstart, 2) ne "--") {
         # skip \n after boundary
         while ( substr(${$r_block}, $attblockstart, 1) =~ /[\n\r]/ ) {
            $attblockstart++;
         }

         $nextboundarystart=index(${$r_block}, "$boundary\n", $attblockstart);
         if ($nextboundarystart == $attblockstart) {
            # this attblock is empty?, skip it.
            $boundarystart=$nextboundarystart;
            $attblockstart=$boundarystart+$boundarylen;
            next;
         } elsif ($nextboundarystart < $attblockstart) {
            # last atblock?
            $nextboundarystart=index(${$r_block}, "$boundary--", $attblockstart);
         }
         if ($nextboundarystart > $attblockstart) {
            # normal attblock handling
            if ( $searchid eq "" || $searchid eq "all") {
               my $r_attachments2=parse_attblock($r_block, $attblockstart, $nextboundarystart-$attblockstart, $subtype, $boundary, "$nodeid-$i", $searchid);
               push(@attachments, @{$r_attachments2});
            } elsif ($searchid eq "$nodeid-$i" || $searchid=~/^$nodeid-$i-/) {
               my $r_attachments2=parse_attblock($r_block, $attblockstart, $nextboundarystart-$attblockstart, $subtype, $boundary, "$nodeid-$i", $searchid);
               push(@attachments, @{$r_attachments2});
               if (defined(${${$r_attachments2}[0]}{'content-type'}) &&
                   ${${$r_attachments2}[0]}{'content-type'} =~ /^text\/html/i ) {
                  $search_html_related_att=1;	# to gather inlined attachment info for this html
               } else {
                  last;	# attblock after this is not the one to look for...
               }
            } elsif ($search_html_related_att) {
               if ($searchid=~/^$nodeid-/) { # an att is html related if it has same parent as html
                  my $r_attachments2=parse_attblock($r_block, $attblockstart, $nextboundarystart-$attblockstart, $subtype, $boundary, "$nodeid-$i", $searchid);
                  push(@attachments, @{$r_attachments2});
               } else {
                  last;	# attblock after this is not related to previous html
               }
            } # else : skip the att
            $boundarystart=$nextboundarystart;
            $attblockstart=$boundarystart+$boundarylen;
         } else {
            # abnormal attblock, last one?
            if ( $searchid eq "" || $searchid eq "all" ||
                 $searchid eq "$nodeid-$i" || $searchid=~/^$nodeid-$i-/ ) {
               my $left=length(${$r_block})-$attblockstart;
               if ($left>0) {
                  my $r_attachments2=parse_attblock($r_block, $attblockstart, $left ,$subtype, $boundary, "$nodeid-$i", $searchid);
                  push(@attachments, @{$r_attachments2});
               }
            }
            last;
         }

         $i++;
      }
      return($header, $body, \@attachments);

   } elsif ($msg{'content-type'} =~ /^message\/partial/i ) {
      if ( $searchid eq "" || $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         my $partialbody=substr(${$r_block}, $headerlen+2);
         my ($partialid, $partialnumber, $partialtotal);
         $partialid=$1 if ($msg{'content-type'} =~ /;\s*id="(.+?)";?/i);
         $partialnumber=$1 if ($msg{'content-type'} =~ /;\s*number="?(.+?)"?;?/i);
         $partialtotal=$1 if ($msg{'content-type'} =~ /;\s*total="?(.+?)"?;?/i);
         my $filename;
         if ($partialtotal) {
            $filename="Partial-$partialnumber.$partialtotal.msg";
         } else {
            $filename="Partial-$partialnumber.msg";
         }
         push(@attachments, make_attachment("","", "Content-Type: $msg{'content-type'}",\$partialbody, length($partialbody),
   	    $msg{'content-transfer-encoding'},"message/partial", "attachment; filename=$filename",$partialid,$partialnumber,$msg{'content-description'}, $nodeid) );
      }
      $body=''; # zero the body since it becomes to message/partial
      return($header, $body, \@attachments);

   } elsif ($msg{'content-type'} =~ /^message\/external\-body/i ) {
      $body=substr(${$r_block}, $headerlen+2);
      my @extbodyattr=split(/;\s*/, $msg{'content-type'});
      shift (@extbodyattr);
      $body="This is an external body reference.\n\n".
            join(";\n", @extbodyattr)."\n\n".
            $body;
      return($header, $body, \@attachments);

   } elsif ($msg{'content-type'} =~ /^message/i ) {
      if ( $searchid eq "" || $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         $body=substr(${$r_block}, $headerlen+2);
         my ($header2, $body2, $r_attachments2)=parse_rfc822block(\$body, "$nodeid-0", $searchid);
         if ( $searchid eq "" || $searchid eq "all" || $searchid eq $nodeid ) {
            $header2 = ow::mime::decode_mimewords($header2);
            my $temphtml="$header2\n\n$body2";
            push(@attachments, make_attachment("","", "",\$temphtml, length($temphtml),
   		$msg{'content-transfer-encoding'},$msg{'content-type'}, "inline; filename=Unknown.msg","","",$msg{'content-description'}, $nodeid) );
         }
         push (@attachments, @{$r_attachments2});
      }
      $body=''; # zero the body since it becomes to header2, body2 and r_attachment2
      return($header, $body, \@attachments);

   } elsif ( $msg{'content-type'} =~ /^text/i || $msg{'content-type'} eq 'N/A' ) {
      $body=substr(${$r_block}, $headerlen+2);
      if ( $searchid eq "" || $searchid eq "all" || $searchid=~/^$nodeid-0/ ) {
         if ( $msg{'content-type'} =~ /^text\/plain/i || $msg{'content-type'} eq 'N/A' ) {
            # mime words inside a text/plain mail, not MIME compliant
            if ($body=~/=\?[^?]*\?[bq]\?[^?]+\?=/si ) {
               $body= ow::mime::decode_mimewords($body);
            }
            # uuencode blocks inside a text/plain mail, not MIME compliant
            if ( $body =~ /^begin [0-7][0-7][0-7][0-7]? [^\n\r]+\n.+?\nend\n/ims ) {
               my $r_attachments2;
               ($body, $r_attachments2)=parse_uuencode_body($body, "$nodeid-0", $searchid);
               push(@attachments, @{$r_attachments2});
            }
         }
      }
      return($header, $body, \@attachments);

   } else {
      if ( $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         $body=substr(${$r_block}, $headerlen+2);
         if ($body=~/\S/ ) { # save att if contains chars other than \s
            push(@attachments, make_attachment("","", "",\$body,length($body),
					$msg{'content-transfer-encoding'},$msg{'content-type'}, "","","",$msg{'content-description'}, $nodeid) );
         }
      } else {
         # null searchid means CGI is in returning html code or in context searching
         # thus content of an non-text based attachment is no need to be returned
         my $bodylength=length(${$r_block})-($headerlen+2);
         my $fakeddata="snipped...";
         push(@attachments, make_attachment("","", "",\$fakeddata,$bodylength,
					$msg{'content-transfer-encoding'},$msg{'content-type'}, "","","",$msg{'content-description'}, $nodeid) );
      }
      return($header, " ", \@attachments);
   }
}

# Handle "message/rfc822,multipart,uuencode inside multipart" encapsulation.
sub parse_attblock {
   my ($r_buff, $attblockstart, $attblocklen, $subtype, $boundary, $nodeid, $searchid)=@_;

   my @attachments=();
   my $attheaderlen=index(${$r_buff},  "\n\n", $attblockstart) - $attblockstart;
   my $attheader=substr(${$r_buff}, $attblockstart, $attheaderlen);
   my $attcontentlength=$attblocklen-($attheaderlen+2);

   my %att; 
   $att{'content-type'}='application/octet-stream;';	# assume att is binary
   parse_header(\$attheader, \%att);
   $att{'content-id'} =~ s/^\s*\<(.+)\>\s*$/$1/;

   if ($att{'content-type'} =~ /^multipart/i) {
      my ($subtype, $boundary, $boundarylen);
      my ($boundarystart, $nextboundarystart, $subattblockstart);
      my $search_html_related_att=0;

      $subtype = $att{'content-type'};
      $subtype =~ s/^multipart\/(.*?)[;\s].*$/$1/i;

      $boundary = $att{'content-type'};
      $boundary =~ s/.*?boundary\s?=\s?"([^"]+)".*$/$1/i or
         $boundary =~ s/.*?boundary\s?=\s?([^\s;]+);?\s?.*$/$1/i;
      $boundary="--$boundary";
      $boundarylen=length($boundary);

      $boundarystart=index(${$r_buff}, $boundary, $attblockstart);
      if ($boundarystart < $attblockstart) {
	 # boundary not found in this multipart block
         # we handle this attblock as text/plain
         $att{'content-type'}=~s!^multipart/\w+!text/plain!i;
         if ( ($searchid eq "all") || ($searchid eq $nodeid) ||
              ($searchid eq "" && $att{'content-type'}=~/^text/i) ) {
            my $attcontent=substr(${$r_buff}, $attblockstart+$attheaderlen+2, $attcontentlength);
            if ($attcontent=~/\S/ ) { # save att if contains chars other than \s
               push(@attachments, make_attachment($subtype,$boundary, $attheader,\$attcontent, $attcontentlength,
                                     @att{'content-transfer-encoding', 'content-type', 'content-disposition', 'content-id', 'content-location', 'content-description'}, 
                                     $nodeid) );
            }
         }
         return(\@attachments);	# return this non-boundaried multipart as text
      }

      my $i=0;
      $subattblockstart=$boundarystart+$boundarylen;
      while ( substr(${$r_buff}, $subattblockstart, 2) ne "--") {
         # skip \n after boundary
         while ( substr(${$r_buff}, $subattblockstart, 1) =~ /[\n\r]/ ) {
            $subattblockstart++;
         }

         $nextboundarystart=index(${$r_buff}, "$boundary\n", $subattblockstart);
         if ($nextboundarystart == $subattblockstart) {
            # this subattblock is empty?, skip it.
            $boundarystart=$nextboundarystart;
            $subattblockstart=$boundarystart+$boundarylen;
            next;
         } elsif ($nextboundarystart < $subattblockstart) {
            $nextboundarystart=index(${$r_buff}, "$boundary--", $subattblockstart);
         }

         if ($nextboundarystart > $subattblockstart) {
            # normal attblock
            if ( $searchid eq "" || $searchid eq "all" ) {
               my $r_attachments2=parse_attblock($r_buff, $subattblockstart, $nextboundarystart-$subattblockstart, $subtype, $boundary, "$nodeid-$i", $searchid);
               push(@attachments, @{$r_attachments2});
            } elsif ( $searchid eq "$nodeid-$i" || $searchid=~/^$nodeid-$i-/ ) {
               my $r_attachments2=parse_attblock($r_buff, $subattblockstart, $nextboundarystart-$subattblockstart, $subtype, $boundary, "$nodeid-$i", $searchid);
               push(@attachments, @{$r_attachments2});
               if (defined(${${$r_attachments2}[0]}{'content-type'}) &&
                   ${${$r_attachments2}[0]}{'content-type'} =~ /^text\/html/i ) {
                  $search_html_related_att=1;	# to gather inlined attachment info for this html
               } else {
                  last;	# attblock after this is not the one to look for...
               }
            } elsif ($search_html_related_att) {
               if ($searchid=~/^$nodeid-/) { # an att is html related if it has same parent as html
                  my $r_attachments2=parse_attblock($r_buff, $subattblockstart, $nextboundarystart-$subattblockstart, $subtype, $boundary, "$nodeid-$i", $searchid);
                  push(@attachments, @{$r_attachments2});
               } else {
                  last;	# attblock after this is not related to previous html
               }
            }
            $boundarystart=$nextboundarystart;
            $subattblockstart=$boundarystart+$boundarylen;
         } else {
            # abnormal attblock, last one?
            if ( $searchid eq "" || $searchid eq "all" ||
                 $searchid eq "$nodeid-$i" || $searchid=~/^$nodeid-$i-/ ) {
               my $left=$attblocklen-$subattblockstart;
               if ($left>0) {
                  my $r_attachments2=parse_attblock($r_buff, $subattblockstart, $left ,$subtype, $boundary, "$nodeid-$i", $searchid);
                  push(@attachments, @{$r_attachments2});
               }
            }
            last;
         }

         $i++;
      }

   } elsif ($att{'content-type'} =~ /^message\/external\-body/i ) {
      if ( $searchid eq "" || $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         my $attcontent=substr(${$r_buff}, $attblockstart+$attheaderlen+2, $attcontentlength);
         my @extbodyattr=split(/;\s*/, $att{'content-type'}); shift (@extbodyattr);
         $attcontent="This is an external body reference.\n\n".
                     join(";\n", @extbodyattr)."\n\n".
                     $attcontent;
         push(@attachments, make_attachment($subtype,$boundary, $attheader,\$attcontent, $attcontentlength,
                               @att{'content-transfer-encoding', 'content-type', 'content-disposition', 'content-id', 'content-location', 'content-description'}, 
                               $nodeid) );
      }

   } elsif ($att{'content-type'} =~ /^message/i ) {
      if ( $searchid eq "" || $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         my $attcontent=substr(${$r_buff}, $attblockstart+$attheaderlen+2, $attcontentlength);
         if ( $att{'content-transfer-encoding'} =~ /^quoted-printable/i) {
            $attcontent = decode_qp($attcontent);
         } elsif ($att{'content-transfer-encoding'} =~ /^base64/i) {
            $attcontent = decode_base64($attcontent);
         } elsif ($att{'content-transfer-encoding'} =~ /^x-uuencode/i) {
            $attcontent = ow::mime::uudecode($attcontent);
         }
         my ($header2, $body2, $r_attachments2)=parse_rfc822block(\$attcontent, "$nodeid-0", $searchid);
         if ( $searchid eq "" || $searchid eq "all" || $searchid eq $nodeid ) {
            $header2 = ow::mime::decode_mimewords($header2);
            my $temphtml="$header2\n\n$body2";
            push(@attachments, make_attachment($subtype,"", $attheader,\$temphtml, length($temphtml),
                                  @att{'content-transfer-encoding', 'content-type', 'content-disposition', 'content-id', 'content-location', 'content-description'}, 
                                  $nodeid) );
         }
         push (@attachments, @{$r_attachments2});
      }

   } elsif ($att{'content-type'} =~ /^text/i || $att{'content-type'} eq "N/A" ) {
      $att{'content-type'}="text/plain" if ($att{'content-type'} eq "N/A");
      if ( $searchid eq "" || $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         my $attcontent=substr(${$r_buff}, $attblockstart+$attheaderlen+2, $attcontentlength);
         if ($attcontent=~/\S/ ) { # save att if contains chars other than \s
            push(@attachments, make_attachment($subtype,$boundary, $attheader,\$attcontent, $attcontentlength,
                                  @att{'content-transfer-encoding', 'content-type', 'content-disposition', 'content-id', 'content-location', 'content-description'}, 
                                  $nodeid) );
         }
      }

   } else {
      if ( $searchid eq "all" || $searchid=~/^$nodeid/ ) {
         my $attcontent=substr(${$r_buff}, $attblockstart+$attheaderlen+2, $attcontentlength);
         if ($attcontent=~/\S/ ) { # save att if contains chars other than \s
            push(@attachments, make_attachment($subtype,$boundary, $attheader,\$attcontent, $attcontentlength,
                                  @att{'content-transfer-encoding', 'content-type', 'content-disposition', 'content-id', 'content-location', 'content-description'}, 
                                  $nodeid) );
         }
      } else {
         # null searchid means CGI is in returning html code or in context searching
         # thus content of an non-text based attachment is no need to be returned
         my $fakeddata="snipped...";
         push(@attachments, make_attachment($subtype,$boundary, $attheader,\$fakeddata,$attcontentlength,
                                  @att{'content-transfer-encoding', 'content-type', 'content-disposition', 'content-id', 'content-location', 'content-description'}, 
                                  $nodeid) );
      }

   }
   return(\@attachments);
}

# convert uuencode block into base64 encoded atachment
sub parse_uuencode_body {
   my ($body, $nodeid, $searchid)=@_;
   my @attachments=();
   my $i;

   # Handle uuencode blocks inside a text/plain mail
   $i=0;
   while ( $body =~ m/^begin ([0-7][0-7][0-7][0-7]?) ([^\n\r]+)\n(.+?)\nend\n/igms ) {
      if ( $searchid eq "" || $searchid eq "all" || $searchid eq "$nodeid-$i" ) {
         my ($uumode, $uufilename, $uubody) = ($1, $2, $3);
         my $uutype;

         $uufilename=~/\.([\w\d]+)$/;
         $uutype=ow::tool::ext2contenttype($1);

         # convert and inline uuencode block into an base64 encoded attachment
         my $uuheader=qq|Content-Type: $uutype;\n|.
                      qq|\tname="$uufilename"\n|.
                      qq|Content-Transfer-Encoding: base64\n|.
                      qq|Content-Disposition: attachment;\n|.
                      qq|\tfilename="$uufilename"|;
         $uubody=encode_base64(ow::mime::uudecode($uubody));

         push( @attachments, make_attachment("","", $uuheader,\$uubody, length($uubody),
		"base64",$uutype, "attachment; filename=$uufilename","","","uuencoded attachment", "$nodeid-$i") );
      }
      $i++;
   }

   $body =~ s/^begin [0-7][0-7][0-7][0-7]? [^\n\r]+\n.+?\nend\n//igms;
   return ($body, \@attachments);
}

# subtype and boundary are inherit from parent attblocks,
# they are used to distingush if two attachments are winthin same group
# note: the $r_attcontent is a reference to the contents of an attachment,
#       this routine will save this reference to attachment hash directly.
#       It means the caller must ensures the variable referenced by
#       $r_attcontent is kept untouched!
sub make_attachment {
   my ($subtype,$boundary, $attheader,$r_attcontent,$attcontentlength,
	$attencoding,$attcontenttype, $attdisposition,$attid,$attlocation,$attdescription, 
        $nodeid)=@_;

   my ($attcharset, $attfilename, $attfilenamecharset);
   $attcharset=$1 if ($attcontenttype=~/charset="?([^\s"';]*)"?\s?/i);
   ($attfilename, $attfilenamecharset)=get_filename_charset($attcontenttype, $attdisposition);

   # guess a better contenttype
   if ( $attcontenttype =~ m!(\Qapplication/octet-stream\E)!i ||
        $attcontenttype =~ m!(\Qvideo/mpg\E)!i ) {
      my ($oldtype, $newtype)=($1, '');
      $attfilename=~ /\.([\w\d]*)$/; $newtype=ow::tool::ext2contenttype($1);
      $attcontenttype=~ s!$oldtype!$newtype!i;
   }
   # remove file=... from disipotion
   $attdisposition =~ s/;.*//;

   return({	# return reference of hash
	subtype		=> $subtype,	# from parent block
	boundary	=> $boundary,	# from parent block
	header		=> $attheader,	# attheader is not decoded yet
	r_content 	=> $r_attcontent,
	'content-length'	=> $attcontentlength,
	'content-type' 		=> $attcontenttype || 'text/plain',
	'content-transfer-encoding'=> $attencoding,
	'content-id' 		=> $attid,
	'content-disposition' 	=> $attdisposition,
	'content-location' 	=> $attlocation,
	'content-description'	=> $attdescription,
	charset		=> $attcharset || '',
	filename 	=> $attfilename,
	filenamecharset => $attfilenamecharset||$attcharset,
	nodeid		=> $nodeid,
	referencecount	=> 0
   });
}

sub get_filename_charset {
   my ($contenttype, $disposition)=@_;
   my ($filename, $filenamecharset);

   $filename = $contenttype;
   if ($filename =~ s/^.+name\s?\*?[:=]\s?"?[\w\d\-]+''([^"]+)"?.*$/$1/i) {
      $filename = ow::tool::unescapeURL($filename);
   } elsif ($filename =~ s/^.+name\s?\*?[:=]\s?"?([^"]+)"?.*$/$1/i) {
      $filenamecharset = $1 if ($filename =~ m{=\?([^?]*)\?[bq]\?[^?]+\?=}xi);
      $filename = ow::mime::decode_mimewords($filename);
   } else {
      $filename = $disposition || '';
      if ($filename =~ s/^.+filename\s?\*?=\s?"?[\w\d\-]+''([^"]+)"?.*$/$1/i) {
         $filename = ow::tool::unescapeURL($filename);
      } elsif ($filename =~ s/^.+filename\s?\*?=\s?"?([^"]+)"?.*$/$1/i) {
         $filenamecharset = $1 if ($filename =~ m{=\?([^?]*)\?[bq]\?[^?]+\?=}xi);
         $filename = ow::mime::decode_mimewords($filename);
      } else {
         $filename = "Unknown.".ow::tool::contenttype2ext($contenttype);
      }
   }
   # the filename of achments should not contain path delimiter,
   # eg:/,\,: We replace it with !
   $filename = ow::tool::zh_dospath2fname($filename, '!');	# dos path
   $filename =~ s|[/:]|!|g;	# / unix patt, : mac path and dos drive

   return($filename, $filenamecharset);
}

sub get_smtprelays_connectfrom_byas_from_header {
   my $header=$_[0]; $header=~s/\s*\n\s+/ /gs;

   my @smtprelays=();
   my %connectfrom=();
   my %byas=();

   foreach (split(/\n/, $header)) {
      if (/^Received:(.+)$/i) {
         my $value=$1;

         # Received: from mail.rediffmailpro.com (mailpro4.rediffmailpro.com [203.199.83.214] (may be forged))
         #	by turtle.ee.ncku.edu.tw (8.12.3/8.12.3) with SMTP id hB4EbqTB066378
         #	for <tung@turtle.ee.ncku.edu.tw>; Thu, 4 Dec 2003 22:37:54 +0800 (CST)
         #	(envelope-from josephotumba@olatunde.net)
         # Received: (qmail 25340 invoked by uid 510); 4 Dec 2003 14:36:27 -0000

         # skip line of MTA self pipe
         # eg: Received: (qmail 25340 invoked by uid 510); 4 Dec 2003 14:36:27 -0000
         # eg: Received: (from tung@localhost) by .....
         next if ($value=~/^ \(.+?\)/);

         if ($value=~/ by\s+(\S+)/i) {
           $smtprelays[0]=$1 if (!defined($smtprelays[0]));	# the last relay on path
           $byas{$smtprelays[0]}=$1;
         }
         if ($value=~/ from\s+(\S+)\s+\((.+?) \(.*?\)\)/i ||
             $value=~/ from\s+(\S+)\s+\((.+?)\)/i ) {
            unshift(@smtprelays, $1); $connectfrom{$1}=$2;
         } elsif ($value=~/ from\s+(\S+)/i ||
                  $value=~/ \(from\s+(\S+)/i ) {
            unshift(@smtprelays, $1);
         }
      }
   }

   # count 1st fromhost as relay only if there are just 2 host on relaylist
   # since it means sender machine uses smtp to talk to our mail server directly
   shift(@smtprelays) if ($#smtprelays>1);

   return(\@smtprelays, \%connectfrom, \%byas);
}

1;

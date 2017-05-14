#
# getmsgids.pl - get/search messageids and related info for msglist in for folderview
#
# The search supports full content search and caches results for repeated queries.
#
use strict;
use Fcntl qw(:DEFAULT :flock);
use MIME::Base64;
use MIME::QuotedPrint;

use vars qw($_OFFSET $_FROM $_TO $_DATE $_SUBJECT $_CONTENT_TYPE $_STATUS $_SIZE $_REFERENCES $_CHARSET);
use vars qw(%config %prefs);
use vars qw(%lang_folders %lang_err);

use vars qw($_index_complete);
sub getinfomessageids {
   my ($user, $folder, $sort, $searchtype, $keyword)=@_;
   my ($folderfile, $folderdb)=get_folderpath_folderdb($user, $folder);

   # do new indexing in background if folder > 10 M && empty db
   if (!ow::dbm::exist($folderdb) && (-s $folderfile) >= 10485760) {
      local $|=1; # flush all output
      local $SIG{CHLD} = sub { wait; $_index_complete=1 if ($?==0) };	# handle zombie
      local $_index_complete=0;
      if ( fork() == 0 ) {		# child
         close(STDIN); close(STDOUT); close(STDERR);
         ow::filelock::lock($folderfile, LOCK_SH|LOCK_NB) or openwebmail_exit(1);
         update_folderindex($folderfile, $folderdb);
         ow::filelock::lock($folderfile, LOCK_UN);
         openwebmail_exit(0);
      }

      for (my $i=0; $i<120; $i++) {	# wait index to complete for 120 seconds
         sleep 1;
         last if ($_index_complete);
      }

      if ($_index_complete==0) {
         openwebmailerror(__FILE__, __LINE__, "$folderfile $lang_err{'under_indexing'}");
      }
   } else {	# do indexing directly if small folder
      ow::filelock::lock($folderfile, LOCK_SH|LOCK_NB) or
         openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_locksh'} $folderfile!");
      if (update_folderindex($folderfile, $folderdb)<0) {
         ow::filelock::lock($folderfile, LOCK_UN);
         openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_updatedb'} db $folderdb");
      }
      ow::filelock::lock($folderfile, LOCK_UN);
   }

   # Since recipients are displayed instead of sender in folderview of
   # SENT/DRAFT folder, the $sort must be changed from 'sender' to
   # 'recipient' in this case
   if ( $folder=~ m#sent-mail#i ||
        $folder=~ m#saved-drafts#i ||
        $folder=~ m#\Q$lang_folders{'sent-mail'}\E#i ||
        $folder=~ m#\Q$lang_folders{'saved-drafts'}\E#i ) {
      $sort='recipient' if ($sort eq 'sender');
   }

   if ( $keyword ne '' ) {
      my $folderhandle=do { local *FH };
      my ($totalsize, $new, $r_haskeyword, $r_messageids, $r_messagedepths);
      my @messageids=();
      my @messagedepths=();

      ($totalsize, $new, $r_messageids, $r_messagedepths)=get_info_messageids_sorted($folderdb, $sort, "$folderdb.cache", $prefs{'hideinternal'});

      ow::filelock::lock($folderfile, LOCK_SH|LOCK_NB) or
         openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_locksh'} $folderfile!");
      open($folderhandle, $folderfile);
      ($totalsize, $new, $r_haskeyword)=search_info_messages_for_keyword(
					$keyword, $prefs{'charset'}, $searchtype, $folderdb, $folderhandle,
					dotpath('search.cache'), $prefs{'hideinternal'}, $prefs{'regexmatch'});
      close($folderhandle);
      ow::filelock::lock($folderfile, LOCK_UN);

      for (my $i=0; $i<@{$r_messageids}; $i++) {
	my $id = ${$r_messageids}[$i];
	if ( ${$r_haskeyword}{$id} == 1 ) {
	  push (@messageids, $id);
	  push (@messagedepths, ${$r_messagedepths}[$i]);
        }
      }
      return($totalsize, $new, \@messageids, \@messagedepths);

   } else { # return: $totalsize, $new, $r_messageids for whole folder
      return(get_info_messageids_sorted($folderdb, $sort, "$folderdb.cache", $prefs{'hideinternal'}))
   }
}

# searchtype: subject, from, to, date, attfilename, header, textcontent, all
# prefs_charset: the charset of the keyword
sub search_info_messages_for_keyword {
   my ($keyword, $prefs_charset, $searchtype, $folderdb, $folderhandle, $cachefile, $ignore_internal, $regexmatch)=@_;
   my ($cache_metainfo, $cache_folderdb, $cache_keyword, $cache_searchtype, $cache_ignore_internal);
   my (%FDB, @messageids, $messageid);
   my ($totalsize, $new)=(0,0);
   my %found=();

   ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or
      return($totalsize, $new, \%found);
   my $metainfo=$FDB{'METAINFO'};
   ow::dbm::close(\%FDB, $folderdb);

   ow::filelock::lock($cachefile, LOCK_EX) or
      return($totalsize, $new, \%found);

   if ( -e $cachefile ) {
      open(CACHE, $cachefile);
      foreach ($cache_metainfo, $cache_folderdb, $cache_keyword, $cache_searchtype, $cache_ignore_internal) {
         $_=<CACHE>; chomp;
      }
      close(CACHE);
   }

   if ( $cache_metainfo ne $metainfo || $cache_folderdb ne $folderdb ||
        $cache_keyword ne $keyword || $cache_searchtype ne $searchtype ||
        $cache_ignore_internal ne $ignore_internal ) {
      $cachefile=ow::tool::untaint($cachefile);
      @messageids=get_messageids_sorted_by_offset($folderdb, $folderhandle);

      ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or return($totalsize, $new, \%found);

      # check if keyword a valid regex
      $regexmatch = $regexmatch && ow::tool::is_regex($keyword);

      foreach $messageid (@messageids) {
         my (@attr, @references, $block, $header, $body, $r_attachments) ;
         @attr=string2msgattr($FDB{$messageid});
         next if ($ignore_internal && is_internal_subject($attr[$_SUBJECT]));
         @references=split(/\s+/, $attr[$_REFERENCES]);

         my $is_conv=is_convertable($attr[$_CHARSET], $prefs_charset);
         if ($is_conv) {
            ($attr[$_FROM], $attr[$_TO], $attr[$_SUBJECT])=
               iconv($attr[$_CHARSET], $prefs_charset, $attr[$_FROM], $attr[$_TO], $attr[$_SUBJECT]);
         }

         # check subject, from, to, date
         if ( ( ($searchtype eq 'all' ||
                 $searchtype eq 'subject') &&
                (($regexmatch && $attr[$_SUBJECT]=~/$keyword/i) ||
                 $attr[$_SUBJECT]=~/\Q$keyword\E/i) )  ||
              ( ($searchtype eq 'all' ||
                 $searchtype eq 'from') &&
                (($regexmatch && $attr[$_FROM]=~/$keyword/i) ||
                 $attr[$_FROM]=~/\Q$keyword\E/i) )  ||
              ( ($searchtype eq 'all' ||
                 $searchtype eq 'to') &&
                (($regexmatch && $attr[$_TO]=~/$keyword/i) ||
                 $attr[$_TO]=~/\Q$keyword\E/i) )  ||
              ( ($searchtype eq 'all' ||
                 $searchtype eq 'date') &&
                (($regexmatch && $attr[$_DATE]=~/$keyword/i) ||
                 $attr[$_DATE]=~/\Q$keyword\E/i) )
            ) {
            $found{$messageid}=1;
         }
         # try to find msgs in same thread with references if seaching subject
         if ($searchtype eq 'subject') {
            foreach my $refid (@references) {
               # if a msg is already in %found, then we put all msgs it references in %found
               $found{$refid}=1 if ($found{$messageid} && defined($FDB{$refid}));
               # if a msg references any member in %found, thn we put this msg in %found
               $found{$messageid}=1 if ($found{$refid});
            }
         }
         if ($found{$messageid}) {
            $new++ if ($attr[$_STATUS]!~/r/i);
            $totalsize+=$attr[$_SIZE];
            next;
         }

	 # check header
         if ($searchtype eq 'all' || $searchtype eq 'header') {
            # check de-mimed header first since header in mail folder is raw format.
            seek($folderhandle, $attr[$_OFFSET], 0);
            $header="";
            while(<$folderhandle>) {
               $header.=$_;
               last if ($_ eq "\n");
            }
            $header = ow::mime::decode_mimewords($header);
            $header=~s/\n / /g;	# handle folding roughly
            ($header)=iconv($attr[$_CHARSET], $prefs_charset, $header) if ($is_conv);

            if ( ($regexmatch && $header =~ /$keyword/im) ||
                 $header =~ /\Q$keyword\E/im ) {
               $new++ if ($attr[$_STATUS]!~/r/i);
               $totalsize+=$attr[$_SIZE];
               $found{$messageid}=1;
               next;
            }
         }

         # read and parse message
         if ($searchtype eq 'all' || $searchtype eq 'textcontent' || $searchtype eq 'attfilename') {
            seek($folderhandle, $attr[$_OFFSET], 0);
            read($folderhandle, $block, $attr[$_SIZE]);
            ($header, $body, $r_attachments)=ow::mailparse::parse_rfc822block(\$block);
         }

	 # check textcontent: text in body and attachments
         if ($searchtype eq 'all' || $searchtype eq 'textcontent') {
            # check body
            if ( $attr[$_CONTENT_TYPE] =~ /^text/i ||
                 $attr[$_CONTENT_TYPE] eq "N/A" ) { # read all for text/plain,text/html
               if ( $header =~ /content-transfer-encoding:\s+quoted-printable/i) {
                  $body = decode_qp($body);
               } elsif ($header =~ /content-transfer-encoding:\s+base64/i) {
                  $body = decode_base64($body);
               } elsif ($header =~ /content-transfer-encoding:\s+x-uuencode/i) {
                  $body = ow::mime::uudecode($body);
               }
               ($body)=iconv($attr[$_CHARSET], $prefs_charset, $body) if ($is_conv);
               if ( ($regexmatch && $body =~ /$keyword/im) ||
                    $body =~ /\Q$keyword\E/im ) {
                  $new++ if ($attr[$_STATUS]!~/r/i);
                  $totalsize+=$attr[$_SIZE];
                  $found{$messageid}=1;
                  next;
               }
            }
            # check attachments
            foreach my $r_attachment (@{$r_attachments}) {
               if ( ${$r_attachment}{'content-type'} =~ /^text/i ||
                    ${$r_attachment}{'content-type'} eq "N/A" ) {	# read all for text/plain. text/html
                  my $content;
                  if ( ${$r_attachment}{'content-transfer-encoding'} =~ /^quoted-printable/i ) {
                     $content = decode_qp( ${${$r_attachment}{r_content}});
                  } elsif ( ${$r_attachment}{'content-transfer-encoding'} =~ /^base64/i ) {
                     $content = decode_base64( ${${$r_attachment}{r_content}});
                  } elsif ( ${$r_attachment}{'content-transfer-encoding'} =~ /^x-uuencode/i ) {
                     $content = ow::mime::uudecode( ${${$r_attachment}{r_content}});
                  } else {
                     $content=${${$r_attachment}{r_content}};
                  }
                  my $attcharset=${$r_attachment}{charset}||$attr[$_CHARSET];
                  if (is_convertable($attcharset, $prefs_charset)) {
                     ($content)=iconv($attcharset, $prefs_charset, $content);
                  }

                  if ( ($regexmatch && $content =~ /$keyword/im) ||
                       $content =~ /\Q$keyword\E/im ) {
                     $new++ if ($attr[$_STATUS]!~/r/i);
                     $totalsize+=$attr[$_SIZE];
                     $found{$messageid}=1;
                     last;	# leave attachments check in one message
                  }
               }
            }
         }

	 # check attfilename
         if ($searchtype eq 'all' || $searchtype eq 'attfilename') {
            foreach my $r_attachment (@{$r_attachments}) {
               my $filename=${$r_attachment}{filename};
               my $attcharset=${$r_attachment}{filenamecharset}||${$r_attachment}{charset}||$attr[$_CHARSET];
               if (is_convertable($attcharset, $prefs_charset)) {
                  ($filename)=iconv($attcharset, $prefs_charset, $filename);
               }
               if ( ($regexmatch && $filename =~ /$keyword/im) ||
                    $filename =~ /\Q$keyword\E/im ) {
                  $new++ if ($attr[$_STATUS]!~/r/i);
                  $totalsize+=$attr[$_SIZE];
                  $found{$messageid}=1;
                  last;	# leave attachments check in one message
               }
            }
         }
      }

      ow::dbm::close(\%FDB, $folderdb);

      open(CACHE, ">$cachefile") or logtime("cache write error $!");
      foreach ($metainfo, $folderdb, $keyword, $searchtype, $ignore_internal) {
         print CACHE $_, "\n";
      }
      print CACHE join("\n", $totalsize, $new, keys(%found));
      close(CACHE);

   } else {
      open(CACHE, $cachefile);
      for (0..4) { $_=<CACHE>; }	# skip 5 lines
      $totalsize=<CACHE>; chomp($totalsize);
      $new=<CACHE>; chomp($new);
      while (<CACHE>) {
         chomp; $found{$_}=1;
      }
      close(CACHE);
   }

   ow::filelock::lock($cachefile, LOCK_UN);

   return($totalsize, $new, \%found);
}

########## GET_MESSAGEIDS_SORTED_BY_...  #########################

sub get_info_messageids_sorted_by_date {
   my ($folderdb, $ignore_internal)=@_;

   my ($totalsize, $total, $new, $r_msgid2attrs)
      =get_info_msgid2attrs($folderdb, $ignore_internal, $_DATE);
   my @messageids= sort {
                        ${${$r_msgid2attrs}{$b}}[0]<=>${${$r_msgid2attrs}{$a}}[0];
                        } keys %{$r_msgid2attrs};

   return($totalsize, $new, \@messageids);
}

sub get_info_messageids_sorted_by_from {
   my ($folderdb, $ignore_internal)=@_;

   my ($totalsize, $total, $new, $r_msgid2attrs)
      =get_info_msgid2attrs($folderdb, $ignore_internal, $_DATE, $_FROM);
   my @messageids= sort {
                        ${${$r_msgid2attrs}{$b}}[0]<=>${${$r_msgid2attrs}{$a}}[0];
                        } keys %{$r_msgid2attrs};

   # try to group message of same 'from'
   my %groupdate=();
   my %groupmembers=();
   foreach my $key (@messageids) {
      my $from=${${$r_msgid2attrs}{$key}}[1];
      if ( !defined($groupdate{$from}) ) {
         my @members=($key);
         $groupmembers{$from}=\@members;
         $groupdate{$from}=${${$r_msgid2attrs}{$key}}[0];
      } else {
         push(@{$groupmembers{$from}}, $key);
      }
   }
   @messageids=();

   # sort group by groupdate
   my @froms=sort {$groupdate{$b} <=> $groupdate{$a}} keys(%groupdate);
   foreach my $from (@froms) {
      push(@messageids, @{$groupmembers{$from}});
   }

   return($totalsize, $new, \@messageids);
}

sub get_info_messageids_sorted_by_to {
   my ($folderdb, $ignore_internal)=@_;

   my ($totalsize, $total, $new, $r_msgid2attrs)
      =get_info_msgid2attrs($folderdb, $ignore_internal, $_DATE, $_TO);
   my @messageids= sort {
                        ${${$r_msgid2attrs}{$b}}[0]<=>${${$r_msgid2attrs}{$a}}[0]
                        } keys(%{$r_msgid2attrs});

   # try to group message of same 'to'
   my %groupdate=();
   my %groupmembers=();
   foreach my $key (@messageids) {
      my $to=${${$r_msgid2attrs}{$key}}[1];
      if ( !defined($groupdate{$to}) ) {
         my @members=($key);
         $groupmembers{$to}=\@members;
         $groupdate{$to}=${${$r_msgid2attrs}{$key}}[0];
      } else {
         push(@{$groupmembers{$to}}, $key);
      }
   }
   @messageids=();

   # sort group by groupdate
   my @froms=sort {$groupdate{$b} <=> $groupdate{$a}} keys %groupdate;
   foreach my $from (@froms) {
      push(@messageids, @{$groupmembers{$from}});
   }

   return($totalsize, $new, \@messageids);
}

sub get_info_messageids_sorted_by_size {
   my ($folderdb, $ignore_internal)=@_;

   my ($totalsize, $total, $new, $r_msgid2attrs)
      =get_info_msgid2attrs($folderdb, $ignore_internal, $_DATE, $_SIZE);
   my @messageids= sort {
                        ${${$r_msgid2attrs}{$b}}[1]<=>${${$r_msgid2attrs}{$a}}[1] or
                        ${${$r_msgid2attrs}{$b}}[0]<=>${${$r_msgid2attrs}{$a}}[0]
                        } keys %{$r_msgid2attrs};

   return($totalsize, $new, \@messageids);
}

sub get_info_messageids_sorted_by_status {
   my ($folderdb, $ignore_internal)=@_;

   my ($totalsize, $total, $new, $r_msgid2attrs)
      =get_info_msgid2attrs($folderdb, $ignore_internal, $_DATE, $_STATUS);

   my %status;
   foreach my $key (keys %{$r_msgid2attrs}) {
      my $status=${${$r_msgid2attrs}{$key}}[1];
      if ($status=~/r/i) {
         $status{$key}=0;
      } else {
         $status{$key}=2;
      }
      $status{$key}++ if ($status=~/i/i);
   }
   my @messageids=sort {
                       $status{$b} <=> $status{$a} or
                       ${${$r_msgid2attrs}{$b}}[0]<=>${${$r_msgid2attrs}{$a}}[0]
                       } keys %status;

   return($totalsize, $new, \@messageids);
}

# this routine actually sorts messages by thread,
# contributed by <james@tiger-marmalade.com"> James Dean Palmer
sub get_info_messageids_sorted_by_subject {
   my ($folderdb, $ignore_internal)=@_;

   my ($totalsize, $total, $new, $r_msgid2attrs)
      =get_info_msgid2attrs($folderdb, $ignore_internal, $_DATE, $_REFERENCES, $_SUBJECT);

   my (%subject, %date);
   foreach my $key (keys %{$r_msgid2attrs}) {
      $date{$key}=${${$r_msgid2attrs}{$key}}[0];
      $subject{$key}=${${$r_msgid2attrs}{$key}}[2];
      $subject{$key}=~s/Res?:\s*//ig;
      $subject{$key}=~s/\[\d+\]//g;
      $subject{$key}=~s/[\[\]]//g;
   }

   my (%thread_parent, @thread_pre_roots, @thread_roots, %thread_children);

   # In the first pass we need to make sure each message has a valid
   # parent message.  We also track which messages won't have parent
   # messages (@thread_roots).
   foreach my $key (keys %date) {
      my @parents = reverse split(/ /, ${${$r_msgid2attrs}{$key}}[1]); # most nearby first
      my $parent = "ROOT.nonexist";	# this should be a string that would never be used as a messageid
      foreach my $id (@parents) {
         if ( defined($subject{$id}) ) {
 	    $parent = $id;
	    last;
         }
      }
      $thread_parent{$key} = $parent;
      $thread_children{$key} = ();
      push @thread_pre_roots, $key if ($parent eq "ROOT.nonexist");
   }

   # Some thread_parent will be completely disconnected, but title is the same
   # so we should connect them with the earliest article by the same title.
   @thread_pre_roots = sort {
                            $subject{$a} cmp $subject{$b} or
                            $date{$a} cmp $date{$b}
                            } @thread_pre_roots;
   my $previous_id = "";
   foreach my $id (@thread_pre_roots) {
      if ($previous_id && $subject{$id} eq $subject{$previous_id}) {
         $thread_parent{$id} = $previous_id;
         $thread_children{$id} = ();
      } else {
         push @thread_roots, $id;
         $previous_id = $id;
      }
   }

   # In the second pass we need to determine which children get
   # associated with which parent.  We do this so we can traverse
   # the thread tree from the top down.
   #
   # We also update the parent date with the latest one of the children,
   # thus late coming message won't be hidden in case it belongs to a
   # very old root
   #
   foreach my $id (sort {$date{$b}<=>$date{$a};} keys %thread_parent) {
      if ($thread_parent{$id} && $id ne "ROOT.nonexist") {
         if ($date{$thread_parent{$id}} lt $date{$id} ) {
            $date{$thread_parent{$id}}=$date{$id};
         }
         push @{$thread_children{$thread_parent{$id}}}, $id;
      }
   }

   my (@message_ids, @message_depths);

   # Finally, we recursively traverse the tree.
   @thread_roots = sort { $date{$a} <=> $date{$b}; } @thread_roots;
   foreach my $key (@thread_roots) {
      _recursively_thread ($key, 0,
		\@message_ids, \@message_depths, \%thread_children, \%date);
   }
   return($totalsize, $new, \@message_ids, \@message_depths);
}

sub _recursively_thread {
   my ($id, $depth,
	$r_message_ids, $r_message_depths, $r_thread_children, $r_date) = @_;

   push @{$r_message_ids}, $id;
   push @{$r_message_depths}, $depth;
   if (defined(${$r_thread_children}{$id})) {
      my @children = sort { ${$r_date}{$a} <=> ${$r_date}{$b}; } @{${$r_thread_children}{$id}};
      foreach my $thread (@children) {
         _recursively_thread ($thread, $depth+1,
	 $r_message_ids, $r_message_depths, $r_thread_children, $r_date);
      }
   }
   return;
}

use vars qw(%sorttype);
%sorttype= (
   'date'          => ['date', 0],
   'date_rev'      => ['date', 1],
   'sender'        => ['sender', 0],
   'sender_rev'    => ['sender', 1],
   'recipient'     => ['recipient', 0],
   'recipient_rev' => ['recipient', 1],
   'size'          => ['size', 0],
   'size_rev'      => ['size', 1],
   'subject'       => ['subject', 1],
   'subject_rev'   => ['subject', 0],
   'status'        => ['status', 0],
   'status_rev'    => ['status', 1]
   );

sub get_info_messageids_sorted {
   my ($folderdb, $sort, $cachefile, $ignore_internal)=@_;
   my ($cache_metainfo, $cache_folderdb, $cache_sort, $cache_ignore_internal);
   my %FDB;
   my ($totalsize, $new)=(0,0);
   my $r_messageids;
   my $r_messagedepths;
   my @messageids=();
   my @messagedepths=();
   my $messageids_size;
   my $messagedepths_size;
   my $rev;

   if (defined($sorttype{$sort})) {
      ($sort, $rev)=@{$sorttype{$sort}};
   } else {
      ($sort, $rev)= ('date', 0);
   }

   ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or 
      return($totalsize, $new, \@messageids, \@messagedepths);
   my $metainfo=$FDB{'METAINFO'};
   ow::dbm::close(\%FDB, $folderdb);

   ow::filelock::lock($cachefile, LOCK_EX) or
      return($totalsize, $new, \@messageids, \@messagedepths);

   if ( -e $cachefile ) {
      open(CACHE, $cachefile);
      foreach ($cache_metainfo, $cache_folderdb, $cache_sort, $cache_ignore_internal, $totalsize) {
         $_=<CACHE>; chomp;
      }
      close(CACHE);
   }

   if ( $cache_metainfo ne $metainfo || $cache_folderdb ne $folderdb ||
        $cache_sort ne $sort || $cache_ignore_internal ne $ignore_internal ||
        $totalsize=~/[^\d]/ ) {
      $cachefile=ow::tool::untaint($cachefile);
      open(CACHE, ">$cachefile");
      print CACHE $metainfo, "\n", $folderdb, "\n", $sort, "\n", $ignore_internal, "\n";
      if ( $sort eq 'date' ) {
         ($totalsize, $new, $r_messageids)=get_info_messageids_sorted_by_date($folderdb, $ignore_internal);
      } elsif ( $sort eq 'sender' ) {
         ($totalsize, $new, $r_messageids)=get_info_messageids_sorted_by_from($folderdb, $ignore_internal);
      } elsif ( $sort eq 'recipient' ) {
         ($totalsize, $new, $r_messageids)=get_info_messageids_sorted_by_to($folderdb, $ignore_internal);
      } elsif ( $sort eq 'size' ) {
         ($totalsize, $new, $r_messageids)=get_info_messageids_sorted_by_size($folderdb, $ignore_internal);
      } elsif ( $sort eq 'subject' ) {
         ($totalsize, $new, $r_messageids, $r_messagedepths)=get_info_messageids_sorted_by_subject($folderdb, $ignore_internal);
      } elsif ( $sort eq 'status' ) {
         ($totalsize, $new, $r_messageids)=get_info_messageids_sorted_by_status($folderdb, $ignore_internal);
      }

      $messageids_size = @{$r_messageids};

      @messagedepths=@{$r_messagedepths} if $r_messagedepths;
      $messagedepths_size = @messagedepths;

      print CACHE join("\n", $totalsize, $new, $messageids_size, $messagedepths_size, @{$r_messageids}, @messagedepths);
      close(CACHE);
      if ($rev) {
         @messageids=reverse @{$r_messageids};
         @messagedepths=reverse @{$r_messagedepths} if $r_messagedepths;
      } else {
         @messageids=@{$r_messageids};
         @messagedepths=@{$r_messagedepths} if $r_messagedepths;
      }

   } else {
      open(CACHE, $cachefile);
      for (0..3) { $_=<CACHE>; }	# skip 4 lines
      foreach ($totalsize, $new, $messageids_size, $messagedepths_size) {
         $_=<CACHE>; chomp;
      }
      my $i = 0;
      while (<CACHE>) {
         chomp;
         if ($rev) {
            if ($i < $messageids_size) { unshift (@messageids, $_); }
            else { unshift (@messagedepths, $_); }
         } else {
            if ($i < $messageids_size) { push (@messageids, $_); }
            else { push (@messagedepths, $_); }
         }
	 $i++;
      }
      close(CACHE);
   }

   ow::filelock::lock($cachefile, LOCK_UN);

   return($totalsize, $new, \@messageids, \@messagedepths);
}

########## END GET_MESSAGEIDS_SORTED_BY_...  #####################

1;

#
# calbook.pl - read/write calbook.pl
#
use strict;
use Fcntl qw(:DEFAULT :flock);

# read the user calendar, put records into 2 hash,
# %items: index -> item fields
# %indexes: date -> indexes belong to this date
# ps: $indexshift is used to shift index so records in multiple calendar
#     won't collide on index
sub readcalbook {
   my ($calbook, $r_items, $r_indexes, $indexshift)=@_;
   my $item_count=0;

   return 0 if (! -f $calbook);

   open(CALBOOK, "$calbook") or return -1;

   while (<CALBOOK>) {
      next if (/^#/);
      chomp;
      my @a=split(/\@{3}/, $_);
      my $index=$a[0]+$indexshift;

      ${$r_items}{$index}={ idate        => $a[1],
                            starthourmin => $a[2],
                            endhourmin   => $a[3],
                            string       => $a[4],
                            link         => $a[5],
                            email        => $a[6],
                            eventcolor   => $a[7]||'none' };

      my $idate=$a[1]; $idate= '*' if ($idate=~/[^\d]/); # use '*' for regex date
      if ( !defined(${$r_indexes}{$idate}) ) {
         ${$r_indexes}{$idate}=[$index];
      } else {
         push(@{${$r_indexes}{$idate}}, $index);
      }
      $item_count++;
   }

   close(CALBOOK);

   return($item_count);
}

sub writecalbook {
   my ($calbook, $r_items)=@_;
   my @indexlist=sort { ${$r_items}{$a}{'idate'}<=>${$r_items}{$b}{'idate'} }
                       (keys %{$r_items});

   $calbook=ow::tool::untaint($calbook);
   if (! -f "$calbook" ) {
      open (CALBOOK,">$calbook") or return -1;
      close(CALBOOK);
   }

   ow::filelock::lock($calbook, LOCK_EX) or return -1;
   open (CALBOOK, ">$calbook") or return -1;
   my $newindex=1;
   foreach (@indexlist) {
      print CALBOOK join('@@@', $newindex, ${$r_items}{$_}{'idate'},
                       ${$r_items}{$_}{'starthourmin'}, ${$r_items}{$_}{'endhourmin'},
                       ${$r_items}{$_}{'string'},
                       ${$r_items}{$_}{'link'},
                       ${$r_items}{$_}{'email'},
                       ${$r_items}{$_}{'eventcolor'})."\n";
      $newindex++;
   }
   close(CALBOOK);
   ow::filelock::lock($calbook, LOCK_UN);

   return($newindex);
}

1;

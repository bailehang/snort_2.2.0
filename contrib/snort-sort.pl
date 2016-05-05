#!/usr/bin/perl
#
# Filename:     snort-sort
# Author:       Andrew R. Baker <andrewb@uab.edu>
# Modified:     2000.03.06
# Purpose:      this script produces a sorted list of snort alerts
#               from a snort alert file
# Version:      0.02
# 
# let me know if you like this and use it  -Andrew
#
# Todo:         1) Allow processing of snort alerts from syslog
#               2) Make html output optional
#
# Change History:
#
# 2000.03.07    reverse DNS lookup 
#                 derived from snort_stat.pl 
#                 and code donated by Adam Olson <adamo@quaartz.com>
#               whois link option
#                 derived from code donated by Adam Olson <adamo@quaartz.com>
#
# 2000.03.06    Original script
#
#
# Options:
#       -r      do reverse DNS lookups  (this can slow things down)
#       -h      produce html output (hardwired)
#       -w      include links to do whois queries on IP addresses
#                       (implies -h)
use Getopt::Std;
use Socket;


if($ARGV[0] eq undef)
{
   print STDERR "USAGE: snort-sort <filename>\n";
   exit;
}

getopts('rhw');
$opt_h = 1;
if($opt_w) {
  $opt_h = 1;
}

# set the whois query href
$whois_href = "http://www.arin.net/cgi-bin/whois.pl?queryinput=";


open(INFILE,"< $ARGV[0]") || die "Unable to open file $ARGV[0]\n";

if($opt_h) {
  print "<html>\n";
  print "<head>\n";
  print "<title>Sorted Snort Alerts</title>\n";
  print "</head>\n";
  print "<body>\n";
  print "<h1>Sorted Snort Alerts</h1><hr>\n";
} else {
  #plain old text output goes here
}

while(<INFILE>) {
  chomp();
  # if the line is blank, go to the next one
  if ( $_ eq "" )  { next }
  # is this line an alert message
  unless ( $_ =~ /^\[\*\*\]/ ) { 
    print STDERR "Warning, file may be corrupt.\n";
    next 
  }
  $a = <INFILE>;
  chomp($a);
  unless ( $a eq "" ) {
    # strip off the [**] from either end.
    s/(\s)*\[\*\*\](\s)*//g;
    push @{ $alerts{$_} }, $a;
  } else {
    print STDERR "Warning, file may be incomplete\n";
  }
}
close(LOG);

if($opt_h) {
  # print out the relative html links to each entry
  foreach $key (keys (%alerts)) {
    $anchor = $key;
    $anchor =~ s/ /_/g;
    print "<a href=#$anchor>$key</a><br>\n";
  }
}

foreach $key (keys (%alerts)) {
  $anchor = $key;
  $anchor =~ s/ /_/g;
  if($opt_h) {
    print "<hr>\n";
    print "<h3><a name=$anchor>$key</a></h3>\n";
    print "<ul>\n";
  } else {
    #plain text output goes here
  }
  @list = @{$alerts{$key}};
  $size = @list;
  for ( $i = 0 ; $i < $size ; $i++ ) {
    $a = $list[$i];
    ($datentime,$src,$arrow,$dest) = split(' ',"$list[$i]");
    ($saddr,$sport) = split(/:/,"$src");
    ($daddr,$dport) = split(/:/,"$dest");
    # reverse DNS lookups
    if($opt_r) {
      $shost = resolve($saddr);
      $dhost = resolve($daddr);
    } else { 
      $shost = $saddr;
      $dhost = $daddr;
    }
    if($opt_w) {
      # if saddr did not resolve (or we did not try to resolve it)
      if(($shost eq $saddr)) {
        $shost = "<a href=$whois_href$saddr>$saddr</a>";
      }
      # same thing for daddr
      if(($dhost eq $daddr)) {
        $dhost = "<a href=$whois_href$daddr>$daddr</a>";
      }
    }
    if($opt_h) {
      print "<li>$datentime $shost:$sport $arrow $dhost:$dport</li>\n";
    } else {
      #plain text output goes here
    }
  }
  if($opt_h) {
    print "</ul>\n";
  } else {
    #plain text output goes here
  }
}
if($opt_h) {
  print "</body></html>\n";
} else {
  #plain text output goes here
}

#
# the following code was taken from snort_stat.pl
#
# resolve host name and cache it
# contributed by: Angelos Karageorgiou, <angelos@stocktrade.gr>
# edited by: $Author: roesch $
#
sub resolve {
  local $mname, $miaddr, $mhost = shift;
  $miaddr = inet_aton($mhost);
  # print "$mhost\n";
  if (!$HOSTS{$mhost}) {
    $mname = gethostbyaddr($miaddr, AF_INET);
    if ($mname =~ /^$/) {
      $mname = $mhost;
    }
    $HOSTS{$mhost} = $mname;
  }
  return $HOSTS{$mhost};
}

#!/usr/bin/perl
#
# $Id: snort_stat.pl,v 1.4 2002/03/20 14:53:35 cazz Exp $
# $Revision: 1.4 $
#
# snort_stat.pl is a perl script trying to generate statistical data from every
# day snort log file.
#
# USAGE: cat <snort_log> | snort_stat.pl -r -f -h -t n
#        -d: debug
#        -r: resolve IP address to domain name
#        -f: use fixed rather than variable width columns
#        -h: produce html output
#        -t: threshold
#
# or put it in the root's crontab file:
#59      10      *       *       *       root    cat /var/log/authlog | /etc/snort_stat.pl | sendmail root
#
# $Author: cazz $
# Yen-Ming Chen, <chenym@ALUMNI.CMU.EDU>
# $Date: 2002/03/20 14:53:35 $
# 

use Getopt::Std;		# use Getopt for options
use Socket;			# use socket for resolving domain name from IP
use vars qw($opt_r $opt_f $opt_d $opt_h $opt_t);
%HOSTS = ();			# Hash for IP <-> domain name mapping  

getopts('drfht:') || die "Could not getopts"; # get options in command line
$saddr_len = 15;
$daddr_len = 15;
$timeout = 3;			# for name resolver
$th = $opt_t || 0;		# default threshold

# process whatever comes in
while (<>) {
  my $alert = {};
  chomp;
  # if the line is blank, go to the next one
  next if $_ eq "";
  # is this line an alert message
  if ( $_ =~ /^\[\*\*\]/ ) {
    $line = <>;
    chomp($line);
    unless ( $line eq "" ) {
      # strip off the [**] from either end.
      s/\s*\[\*\*\]\s*//og;
      s/\s*\[[0-9:]+\]\s*//o;
      if ($_ =~ /^spp_anomsensor\:[\D]+\:\s([\d\.]+)/ox) {
        $alert->{PLUGIN} = "anomsensor"; $alert->{TYPE} = "plugin";
        $alert->{SIG} = $alert->{PLUGIN};
      } elsif ($_ =~ /^spp_portscan\:\sEnd\sof\sportscan\sfrom\s([\d\.]+)/ox) {
        $alert->{PLUGIN} = "portscan"; $alert->{TYPE} = "plugin";
        $alert->{SADDR} = $1; $alert->{SIG} = $alert->{PLUGIN};
        process_data($alert); $lastwassnort = 1; next;
      } elsif ( $_ =~ /^spp_stream4\:\s(.+)/o ) {
        $alert->{SIG} = $1; $alert->{TYPE} = "alert";
	$alert->{PLUGIN} = "stream";
      } elsif ( $_ =~ /[^:]/ox) {
        $alert->{SIG} = $_; $alert->{TYPE} = "alert"; 
      }
      if ( $line =~ m/^\[Classification\:([^\]]*)\]\s
	   \[Priority\:\s(\d+)\]/ox) {
        $alert->{CLASS} = $1; $alert->{CONTENT} = $2; $alert->{PRIORITY} = $3;
	$line=<>;
      }
      if ( $line =~ m/^(\d+)\/(\d+)\-(\d+)\:(\d+)\:(\d+)\.(\d+)\s
	   ([\d\.]+)[\:]*([\d]*)\s[\-\>]+\s([\d\.]+)[\:]*([\d]*)/ox) {
        $alert->{MON} = $1;   $alert->{DAY} = $2;   $alert->{HOUR} = $3; 
        $alert->{MIN} = $4;   $alert->{SEC} = $5;   $alert->{SADDR} = $7; 
        $alert->{SPORT} = $8; $alert->{DADDR} = $9; $alert->{DPORT} = $10; 
        $alert->{HOST} = "localhost"; 
        process_data($alert); $lastwassnort = 1; next;
      }
    } else { 
      print STDERR "Warning, file may be incomplete\n";
      next;
    }
  } 
  # This is syslog format
  if ($_ =~ m/^(\w{3}) \s+ (\d+) \s (\d+)\:(\d+)\:(\d+)\s 
                   (\S+?)\ssnort[\[\d+\]]*\:\s+(.+)/ox 
      || m/^(\d+)\/(\d+)\-(\d+)\:(\d+)\:(\d+)\.(\d+)\s(.+)/ox) 
  {
    $alert->{MON} = $1;    $alert->{DAY} = $2;    $alert->{HOUR} = $3; 
    $alert->{MIN} = $4;    $alert->{SEC} = $5;    $alert->{HOST} = $6;  
    $alert->{SIG} = $7;    
    $alert->{SIG} =~ s/\s*\[[\d\:]+\]\s*//;  # Get rid of [343:33:31]
    $alert->{SIG} =~ s/\[\*\*\]//og; # Get rid of [**] if fast alert
    if ($alert->{SIG} =~ m/spp_portscan\:\sEnd\sof\sportscan\sfrom\s
	([\d\.]+)/ox) { # portscan
      $alert->{SADDR} = $1; $alert->{TYPE} = "plugin"; 
      $alert->{PLUGIN} = "portscan";
      process_data($alert); $lastwassnort = 1; next;
    } elsif ( $alert->{SIG} =~ s/\s([\d\.]+)[\:]?([\d]*)\s[\-\>]+\s
                            ([\d\.]+)[\:]?([\d]*)\s*//x) {
      $alert->{SADDR} = $1; $alert->{SPORT} = $2; 
      $alert->{DADDR} = $3; $alert->{DPORT} = $4; 
      if ($alert->{SIG} =~ m/spp_anomsensor\:\sAnomaly\sthreshold\s
	  exceeded\:\s([\d\.]+)/ox) { # spade
	$alert->{THR} = $1; $alert->{TYPE} = "plugin"; 
	$alert->{PLUGIN} = "anomsensor";
	process_data($alert); $lastwassnort = 1; next;
      } elsif ($alert->{SIG} =~ s/spp_bo\:\s//ox) { # bo
	$alert->{TYPE} = "plugin"; $alert->{PLUGIN} = "bo";
	process_data($alert); $lastwassnort = 1; next;
      } elsif ($alert->{SIG} =~ s/spp_stream4\:\s//ox) { # stream4 
        $alert->{TYPE} = "plugin"; $alert->{PLUGIN} = "stream";
        process_data($alert); $lastwassnort = 1; next;
      } else { # normal alert
	if ( $alert->{SIG} =~ s/\[Classification\:([^\[|^\]]*?)\]\s*
	     (?:\[Priority\:\s(\d+)\])//x ) {
	  $alert->{CLASS} = $1;  $alert->{PRIORITY} = $2;
        }
	$alert->{TYPE} = "sys"; $alert->{PLUGIN} = "none";
	process_data($alert); $lastwassnort = 1; next;
      }
    } else {
      print STDERR "No source/dest IP address found! Skipped!" if $opt_d; 
      $alert = {}; next;
    }
  }
  # If a snort message has been repeated several times
  elsif ($lastwassnort && $_ =~ m/last message repeated (\d+) times/) {
    # put the data in the matrix again for each repeat
    $repeats = $1;
    while ($repeats) {
      push @result, $result[-1];
      $repeats--;
    }
    next;
  } else {
    $lastwassnort = 0;
    next;
  }				# Message not related to snort
}

# begin statistics
# I should've used $#result + 1 as $total in the first version! :(
$total = $#result + 1;

for $i ( 0 .. $#result ) {
  # for the same pair of attacker and victim with same sig
  # to see the attack pattern
  # used in same_attack()
  $s0{"$result[$i]->[9],$result[$i]->[7],$result[$i]->[6]"}++;
  # for the same pair of attacker and victim 
  # to see how many ways are being tried
  # used in same_host_dest()
  $s1{"$result[$i]->[7],$result[$i]->[9]"}++;
  # from same host use same method to attack 
  # to see how many attacks launched from one host
  # used in same_host_sig()
  $s2{"$result[$i]->[6],$result[$i]->[7]"}++;
  # to same victim with same method
  # to see how many attacks received by one host
  # used in same_dest_sig_stat()
  $s3{"$result[$i]->[6],$result[$i]->[9]"}++;
  # same signature
  # to see the popularity of one attack method
  # used in attack_distribution()
  $s4{"$result[$i]->[6]"}++;
  # source ip
  $s5{"$result[$i]->[7]"}++;
  # destination ip
  $s6{"$result[$i]->[9]"}++;
}

# begin report

print_head();
print_summary();
print_menu();
same_attack();
same_host_dest();
same_host_sig();
same_dest_sig_stat();
attack_distribution();
if ($opt_p) {
  portscan();
}
if ($opt_n) {
  anomsensor();
}
print_footer();

# print the header (e.g. for mail)
sub print_head {
  if ($opt_h) {
    print "<html>\n<head>\n";
    print "<title>Snort Statistics</title>";
    print "</head>\n<body>\n";
    print "<h1>Snort Statistics</h1>\n";
  } else { 
    print "Subject: snort daily report\n\n";
  }
}

# print the time of begin and end of the log
sub print_summary {
  if ($opt_h) {
    print "<table>\n";
    print "<tr><th>The log begins at:</th>\n";
    print "<td>$result[0]->[0] $result[0]->[1] $result[0]->[2]:$result[0]->[3]:$result[0]->[4]</td></tr>\n";
    print "<tr><th>The log ends at:</th>\n";
    print "<td>$result[$#result]->[0] $result[$#result]->[1] $result[$#result]->[2]:$result[$#result]->[3]:$result[$#result]->[4]</td></tr>\n";
    print "<tr><th>Total events:</th><td> $total</td></tr>\n";
    print "<tr><th>Signatures recorded:</th><td> ". keys(%s4) ."</td></tr>\n";
    print "<tr><th>Source IP recorded:</th><td> ". keys(%s5) ."</td></tr>\n";
    print "<tr><th>Destination IP recorded:</th><td> ". keys(%s6) ."</td></tr>\n";
    print "<tr><th>Portscan detected:</th><td> ", eval '$#posres +1',"</td></tr>\n" if $opt_p;
    print "<tr><th>Anomaly detected:</th><td> ", eval '$#anores +1',"</td></tr>\n" if $opt_n;
    print "</table>\n";
    print "<hr>\n";
  } else {
    print "The log begins from: $result[0]->[0] $result[0]->[1] $result[0]->[2]:$result[0]->[3]:$result[0]->[4]\n";
    print "The log ends     at: $result[$#result]->[0] $result[$#result]->[1] $result[$#result]->[2]:$result[$#result]->[3]:$result[$#result]->[4]\n";
    print "Total events: $total\n";
    print "Signatures recorded: ". keys(%s4) ."\n";
    print "Source IP recorded: ". keys(%s5) ."\n";
    print "Destination IP recorded: ". keys(%s6) ."\n";
    print "Portscan recorded: ", eval '$#posres +1',"\n" if $opt_p;
    print "Anomaly recorded: ", eval '$#anores +1',"\n" if $opt_n;
  }
}

# print menu for HTML page
sub print_menu {
  if ($opt_h) {
    print "<ul><a name=\"top\"></a>\n";
    print "<li><a href=\"#same_hdm\">Number of attacks from same host to same destination with same method</a>\n"; 
    print "<li><a href=\"#same_hd\">Percentage and number of attacks from a host to a destination</a>\n";
    print "<li><a href=\"#same_hm\">Percentage and number of attacks from one host to any with same method</a>\n";
    print "<li><a href=\"#same_d\">Percentage and number of attacks to one certain host</a>\n";
    print "<li><a href=\"#same_m\">Distribution of attack methods</a>\n";
    print "<li><a href=\"#portscan\">Portscans performed to/from HOME_NET</a>\n" if $opt_p;
    print "<li><a href=\"#spade\">Anomaly detected by SPADE</a>\n" if $opt_n;
    print "</ul><HR>\n";
  }
}

# to see the frequency of the attack from a certain pair of 
# host and destination
sub same_attack {
  if ($opt_h) {
    print "<h3><a name=\"same_hdm\">Number of attack from same host to same destination using same method</a></h3>\n";
    print "<table>\n";
    print "<tr><th># of attacks</th><th>from</th><th>to</th><th>with</th></tr>";
    foreach $k (sort { $s0{$b} <=> $s0{$a} } keys %s0) { 
      @_ = split ",",$k;
      print "<tr><td>$s0{$k}</td><td>$_[1]</td><td>$_[0]</td>
             <td>".printHref($_[2])."</td></tr>\n" if $s0{$k} > $th;
    }
    print "</table><a href=\"#top\">Top</a><hr>\n";
  } else {
    section_header("The number of attacks from same host to same
destination using same method\n", "asdm");
    foreach $k (sort { $s0{$b} <=> $s0{$a} } keys %s0) { 
      @_ = split ",",$k;
      printf("   %-2d     %-${saddr_len}s   %-${daddr_len}s   %-20s\n",
	     $s0{$k},$_[1],$_[0],$_[2]) if $s0{$k} > $th;
    }
  }
}

# to see the percentage and number of attacks from a host to a destination
sub same_host_dest {
  if ($opt_h) {
    print "<h3><a name=\"same_hd\">Percentage and number of attacks from a host to a destination</a></h3>\n";
    print "<table>\n";
    print "<tr><th>%</th><th># of attacks</th><th>from</th><th>to</th></tr>\n";
    foreach $k (sort { $s1{$b} <=> $s1{$a} } keys %s1) {
      @_ = split ",",$k;
      printf("<tr><td>%-2.2f</td><td>%-2d</td><td>%-20s</td><td>%-20s</td>
              <td>\n",$s1{$k}/$total*100,$s1{$k},$_[0],$_[1]) if $s1{$k} > $th;
    }
    print "</table><a href=\"#top\">Top</a><hr>\n";
  } else {
    section_header("Percentage and number of attacks from a host to a
destination\n", "pasd");  
    foreach $k (sort { $s1{$b} <=> $s1{$a} } keys %s1) {
      @_ = split ",",$k;
      printf("%5.2f    %-2d      %-${saddr_len}s   %-${daddr_len}s\n",
	     $s1{$k}/$total*100, $s1{$k},$_[0],$_[1]) if $s1{$k} > $th;
    }
  }
}

# to see how many attacks launched from one host
sub same_host_sig {
  if ($opt_h) {
    print "<h3><a name=\"same_hm\">Percentage and number of attacks from one host to any with same method</a></h3>\n";
    print "<table>\n";
    print "<tr><th>%</th><th># of attacks</th><th>from</th><th>type</th></tr>\n";
    foreach $k (sort { $s2{$b} <=> $s2{$a} } keys %s2) {
      @_ = split ",",$k;
      printf("<tr><td>%-2.2f</td><td>%-4d</td><td>%-20s</td><td>%-28s</td>
             </tr>\n",$s2{$k}/$total*100,$s2{$k},$_[1],&printHref($_[0])) if $s2{$k} > $th;
    }
    print "</table><a href=\"#top\">Top</a><hr>\n";
  } else { 
    section_header("Percentage and number of attacks from one host to any
with same method\n", "pasm");  
    foreach $k (sort { $s2{$b} <=> $s2{$a} } keys %s2) {
      @_ = split ",",$k;
      printf("%5.2f    %-4d    %-${saddr_len}s   %-28s\n",
	     $s2{$k}/$total*100, $s2{$k},$_[1],$_[0]) if $s2{$k} > $th;
    }
  }
}

# to see how many attacks received by one host (destination correlated)
sub same_dest_sig_stat {
  if ($opt_h) {
    print "<h3><a name=\"same_d\">Percentage and number of attacks to one certain host</a></h3>\n";
    print "<table>\n";
    print "<tr><th>%</th><th># of attacks</th><th>to</th><th>type</th></tr>\n";
    foreach $k (sort { $s3{$b} <=> $s3{$a} } keys %s3) {
      @_ = split ",",$k;
      printf("<tr><td>%-2.2f</td><td>%-4d</td><td>%-25s</td><td>%-28s</td><td>\n",$s3{$k}/$total*100,$s3{$k},$_[1],&printHref($_[0])) if $s3{$k} > $th;
    }
    print "</table><a href=\"#top\">Top</a><hr>\n";
  } else {
    section_header("Percentage and number of attacks to one certain host \n", "padm");
    foreach $k (sort { $s3{$b} <=> $s3{$a} } keys %s3) {
      @_ = split ",",$k;
      printf("%5.2f    %-4d    %-${daddr_len}s  %-28s\n",$s3{$k}/$total*100 ,
	     $s3{$k},$_[1],$_[0]) if $s3{$k} > $th;
    }
  }
}

# to see the popularity of one attack method
sub attack_distribution {
  if ($opt_h) {
    print "<h3><a name=\"same_m\">Distribution of attack methods</a></h3>\n";
    print "<table>\n";
    print "<tr><th>%</th><th># of attacks</th><th>methods</th></tr>\n";
    foreach $k (sort { $s4{$b} <=> $s4{$a} } keys %s4) {
      @p1 = split ":",$k;
      if ($s4{$k} > $th) {
        printf("<tr><td>%-2.2f</td><td><B>%-4d</B></td><td><B>%-32s</B></td>
                </tr>\n", $s4{$k}/$total*100,$s4{$k},&printHref($p1[0])); 
        foreach $k2 (sort { $s0{$b} <=> $s0{$a} } keys %s0) {
          @p2 = split ",",$k2;
          printf("<tr><td></td><td>%-4d</td><td>%-32s</td></tr>\n", $s0{$k2}, join(" -> ", $p2[1],$p2[0])) if $p1[0] eq $p2[2];
        }
      }
    }
    print "</table><a href=\"#top\">Top</a><hr>\n";
  } else {
    section_header("The distribution of attack methods\n", "pam");
    foreach $k (sort { $s4{$b} <=> $s4{$a} } keys %s4) {
      @p1 = split ":",$k;
      if ($s4{$k} > $th) {
        printf("%5.2f    %-4d    %-32s\n", $s4{$k}/$total*100,$s4{$k},$p1[0]); 
        foreach $k2 (sort { $s0{$b} <=> $s0{$a} } keys %s0) {
          @p2 = split ",",$k2;
          printf("\t\t %-4d  %-${saddr_len}s -> %-${daddr_len}s\n", $s0{$k2}, $p2[1],$p2[0]) if $p1[0] eq $p2[2];
        }
      }
    }
  }
}

# portscan (if enable -p switch)
# Please use '-A fast' to generate the log, so portscan() can process it.
# contributed by: Paul Bobby, <paul.bobby@lmco.com>
#                 Jian-Da Li, <jdli@freebsd.csie.nctu.edu.tw>
sub portscan {
  my (%s7, %s8);
  # to see how many times a host performs portscan
  # used in portscan()
  for $i (0 .. $#posres) {
    $s7{"$posres[$i]->[0]"}++;
  }
  if ($opt_h) {
    print "<h3><a name=\"portscan\">Portscans performed to/from HOME_NET</a></h3>\n";
    print "<table>\n";
    print "<tr><th>Scan Attempts</th><th>Source Address</th></tr>\n";
    foreach $k (sort { $s7{$b} <=> $s7{$a} } keys %s7) {
      print "<tr><td>$s7{$k}</td><td>$k</td></tr>\n" if $s7{$k} > $th;
    }
    print "</table><a href=\"#top\">Top</a><HR>\n";
  } else {
    section_header("Portscans performed to/from HOME_NET\n", "as");
    foreach $k (sort { $s7{$b} <=> $s7{$a} } keys %s7) {
      printf(" %-4d    %-${saddr_len}s\n", $s7{$k},$k) if $s7{$k} > $th;
    }
  }
}

# anomsensor (if enable -n switch)
# This function process data generated by spp_anomsensor plug-in (SPADE)
# By Yen-Ming Chen <chenym@alumni.cmu.edu>
sub anomsensor {
  my (%s7);
  # to see how many times a host performs portscan
  # used in anomsensor()
  for $i (0 .. $#anores) {
    $s7{"$anores[$i]->[1],$anores[$i]->[3],$anores[$i]->[4]"}++;
  }
  if ($opt_h) {
    print "<h3><a name=\"spade\">Anomaly detected by SPADE</a></h3>\n";
    print "<table>\n";
    print "<tr><th>Scan Attempts</th><th>Source Address</th><th>Destination Address</th><th>Destination Ports</th></tr>\n";
    foreach $k (sort { $s7{$b} <=> $s7{$a} } keys %s7) {
      @_ = split(/,/,$k);
      print "<tr><td>$s7{$k}</td><td>$_[0]</td><td>$_[1]</td><td>$_[2]</td></tr>\n" if $s7{$k} > $th;
    }
    print "</table><a href=\"#top\">Top</a><HR>\n";
  } else {
    section_header("Anomaly detected by SPADE\n", "asdo");
    foreach $k (sort { $s7{$b} <=> $s7{$a} } keys %s7) {
      @_ = split(/,/,$k);
      printf("   %-4d   %-${saddr_len}s %-${daddr_len}s\t%-6d\n", $s7{$k},$_[0],$_[1],$_[2]) if $s7{$k} > $th;
    }
  }
}

# print the footer (needed for html)
sub print_footer {
  if ($opt_h) { 
    print "Generated by <a href=\"http://xanadu.incident.org/snort/\">snort_stat.pl</a>\n";
    print "</body>\n</html>\n";
  } 
}

#
# resolve host name and cache it
# contributed by: Angelos Karageorgiou, <angelos@stocktrade.gr>
# edited by: $Author: cazz $
#
sub resolve {
  local ($mname, $miaddr, $mhost = shift);
  $miaddr = inet_aton($mhost);
  if (!$HOSTS{$mhost}) {
    $mname ="";
    eval {
      local $SIG{ALRM} = sub {die "alarm\n" }; # NB \n required
      alarm $timeout;
      $mname = gethostbyaddr($miaddr, AF_INET);
      alarm 0;
    };
    die if $@ && $@ ne "alarm\n"; # propagate errors
    if ($mname =~ /^$/) {
      $mname = $mhost;
    }
    $HOSTS{$mhost} = $mname;
  }
  return $HOSTS{$mhost};
}

# Use a title and a short code to write the section headers
# This is used in place of a FORMAT as this allows variable column widths
# contributed by: Ned Patterson, <jpatter@alum.mit.edu>
#
sub section_header {
  my $linelength;
  $title = shift; 
  $_ = shift;
  print("\n\n$title");
  # constant for method length for now
  $linelength = (/p/?7:0) + (/a/?20:0) + (/s/?$saddr_len:0) +
    (/d/?$daddr_len+3:0) + (/m/?20:0);
  print( '=' x $linelength, "\n");
  print(" " x 7, " #  of\n")           if (/pa.*/);
  print("  # of\n attacks  ")          if (s/^a([sdm]*)/$1/);
  print("  %    ")                     if (s/^p([asdm]*)/$1/);
  print("attacks   ")                  if (s/^a([sdm]*)/$1/);
  printf("%-${saddr_len}s   ", "from") if (s/^s([dm]*)/$1/);
  printf("%-${daddr_len}s   ", "to"  ) if (s/^d(m*)/$1/);
  printf("%-5s   ", "ports"  )         if (s/^o(m*)/$1/);
  print("method")                      if (/^m/);
  print("\n");
  
  print( '=' x $linelength, "\n");
}

# Put data $alert into matrix for further process
# INPUT: $alert
sub process_data() {
  $self = shift;
  # if the resolve switch is on
  if ($opt_r) {
    $self->{SADDR} = resolve($self->{SADDR});
    unless ($opt_f) {
      if ( length($self->{SADDR}) > $saddr_len ) {
	$saddr_len = length($self->{SADDR});
      }
    }
    $self->{DADDR} = resolve($self->{DADDR});
    unless ($opt_f) {
      if ( length($self->{DADDR}) > $daddr_len ) {
	$daddr_len = length($self->{DADDR});
      }
    }
  }
  # put those data into a big matrix
  if ($self->{PLUGIN} eq "anomsensor") {
    push @anores , [$self->{THR},$self->{SADDR},$self->{SPORT},
                    $self->{DADDR},$self->{DPORT}];
    $opt_n = 1;
  } elsif ($self->{PLUGIN} eq "portscan") {
    push @posres , [$self->{SADDR}];
    $opt_p = 1;
  } elsif ($self->{TYPE} eq "sys" || $self->{TYPE} eq "alert" || 
	   $self->{PLUGIN} eq "stream" || $self->{PLUGIN} eq "bo" ) {
    $self->{SIG} =~ s/\:$//o;
    push @result ,[$self->{MON},$self->{DAY},$self->{HOUR},$self->{MIN},
                   $self->{SEC},$self->{HOST},$self->{SIG},$self->{SADDR},
                   $self->{SPORT},$self->{DADDR},$self->{DPORT}];
    $lastwassnort = 1;
  } else {
    print STDERR "Unknown alert type/plugin! $self->{TYPE}:$self->{PLUGIN} Skipped!\n";
    return;
  }
  1;
}

# Turn IDS into the link to whitehats
sub printHref
{
  my $type = $_[0];

  if ($type =~ /\A\s*(IDS\d+)\//) 
    {
      return "<a href=\"http://www.whitehats.com/info/$1\" 
            target=\"_blank\">$type</a>";
    }
  return $type;
}

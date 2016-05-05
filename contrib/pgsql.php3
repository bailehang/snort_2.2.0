<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<html>
  <head>
    <title>Snort Statistics On-Line</title>
<!-- Html Comments begin here

This is Snort Statistics On-Line PHP script. You need to have php with support of postgresql database. Then just put this file under the directory you allow php to be executed, or name it as foobar.php3. It looks more like http://www.incident.org/ now, but I hope to make it more 'interactive' in the future, or at least do something like my snort_stat.pl does. :)

Oh, there is not many comments here. :)

$Id: pgsql.php3,v 1.1.1.1 2000/08/07 02:42:53 roesch Exp $
Yen-Ming Chen <chenym@CMU.EDU>

$Log: pgsql.php3,v $
Revision 1.1.1.1  2000/08/07 02:42:53  roesch
Initial Import


Revision 1.1  2000/05/02 02:28:59  yenming
Snort Statistic PHP3 script for Postgresql by Yen-Ming Chen
<chenym@CMU.EDU>
New committed for new Snort database scheme.


-->
  </head>

  <body>
    <h1>Snort Statistics On-Line</h1>

<?php
// Turn a postgresql time duration output into seconds
function turn_sec($string) {
  $duration = preg_split("/\s/",substr($string,2));
  switch(count($duration)) {
    case 0:
    case 1:
    case 3:
    case 5:
    case 7:
      break;
    case 2:
      $seconds = $duration[0];
      break;
    case 4:
      $seconds = $duartion[2] + $duration[0]*60;
      break;
    case 6:
      $seconds = $duration[4] + $duration[2]*60 + $duration[0]*3600;
      break;
    case 8:
      $seconds = $duration[6] + $duration[4]*60 + $duration[2]*3600 + $duration[0]*86400;
      break;
    default:
      break;
  }
  return $seconds;
}

 /* The parameters here assume you use postgresql on localhost, and run this php script as a valid user to access the database */
 $pg_connection = pg_connect("","","","","snort");  
?>

<h2>Summary</h2>
<?php
  $Selstr="SELECT COUNT(event.cid),MIN(event.timestamp),MAX(event.timestamp) FROM event";
  $Selstr2="SELECT DISTINCT signature FROM event";
  $Selstr3="SELECT ip_src0,ip_src1,ip_src2,ip_src3 FROM iphdr GROUP BY ip_src0,ip_src1,ip_src2,ip_src3";
  $Selstr4="SELECT ip_dst0,ip_dst1,ip_dst2,ip_dst3 FROM iphdr GROUP BY ip_dst0,ip_dst1,ip_dst2,ip_dst3";
  $Result=pg_exec($pg_connection,$Selstr);
  $Result2=pg_exec($pg_connection,$Selstr2);
  $Result3=pg_exec($pg_connection,$Selstr3);
  $Result4=pg_exec($pg_connection,$Selstr4);

  if (pg_NumRows($Result2) == 1) {
    $tot_sig = pg_NumRows($Result2);
  } else {
    $tot_sig = 0;
  }
  if (pg_NumRows($Result3) == 1) {
    $tot_dip = pg_NumRows($Result3);
  } else {
    $tot_dip = 0;
  }
  if (pg_NumRows($Result4) == 1) {  
    $tot_sip = pg_NumRows($Result4);
  } else {
    $tot_sip = 0;
  }
  if (pg_NumRows($Result) != 0) {
    $row = pg_fetch_row($Result,0);
    print "Total events: $row[0]<br>\n
           Timestamp begins at: $row[1]<br>\n
           Timestamp ends at: $row[2]<br>\n
           Total signatures: $tot_sig<br>\n
           Total Destination IP observed: $tot_dip<br>\n
           Total Source IP observed: $tot_sip<br>\n";
  }
  else {
    print "Nothing Here\n";
  }
  pg_freeresult($Result);
  pg_freeresult($Result2);
  pg_freeresult($Result3);
  pg_freeresult($Result4);
?>
<HR>
<H2><a name="top">Table Of Contents</a></H2>
    <ul>
      <li><a href="#tcp">10 most recent TCP probes</a></li>
      <li><a href="#udp">10 most recent UDP probes</a></li>
      <li><a href="#icmp">10 most recent ICMP probes</a></li>
      <li><a href="#by_signature">Reports by signatures</a></li>
      <li><a href="#source_sig">From same source with same signature</a></li>
      <li><a href="#yourip">Scans to yourhost</a></li>
    </ul>
<a name="tcp"><HR></a>
<?php
 $Selstr="SELECT event.signature,event.timestamp,iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,tcphdr.th_sport,tcphdr.th_dport FROM event,iphdr,tcphdr WHERE iphdr.sid = event.sid and iphdr.cid = event.cid and tcphdr.cid = event.cid ORDER BY event.timestamp DESC LIMIT 10";
 $Result=pg_exec($pg_connection,$Selstr); 

?>
<TABLE BORDER="2" CELLPADDING="5">
    <TR BGCOLOR="#CCCCCC"><TH COLSPAN="5" ALIGN="center">10 most recent TCP probe reports</B></TH></TR>
    <TR BGCOLOR="#CCCCCC"><TD>Timestamp</TD><TD>Source IP</TD><TD>Source Port</TD><TD>Dest Port</TD><TD>Signature</TD>
<?php
  if (pg_NumRows($Result) != 0) {
    for ($i = 0; $i < pg_NumRows($Result); $i++ ) {
      $row = pg_fetch_row($Result,$i);
      print "<tr bgcolor=\"white\"><td>$row[1]</td>\n
        <td>$row[2].$row[3].$row[4].$row[5]</td>\n
        <td>$row[6]</td>\n
        <td>$row[7]</td>\n
        <td>$row[0]</td>\n";
    }
  }
  else {
    print "<tr><th colspan=5 align=center>Nothing there!</th></tr>\n";
  }
  pg_freeresult($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="udp"><HR></a>
<?php
 $Selstr="SELECT event.signature,event.timestamp,iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,udphdr.uh_sport,udphdr.uh_dport FROM event,iphdr,udphdr WHERE iphdr.sid = event.sid AND iphdr.cid = event.cid AND udphdr.sid = iphdr.sid AND udphdr.cid = iphdr.cid ORDER BY event.timestamp DESC LIMIT 10;";
 $Result=pg_exec($pg_connection,$Selstr); 
?>
<TABLE BORDER="2" CELLPADDING="5">
    <TR BGCOLOR="#CCCCCC"><TH COLSPAN="5" ALIGN="center">10 most recent UDP probe reports</B></TH></TR>
    <TR BGCOLOR="#CCCCCC"><TD>Timestamp</TD><TD>Source IP</TD><TD>Source Port</TD><TD>Dest Port</TD><TD>Signature</TD>
<?php
  if (pg_NumRows($Result) != 0) {
    for ($i = 0; $i < pg_NumRows($Result); $i++ ) {
      $row = pg_fetch_row($Result,$i);
    print "<tr bgcolor=\"white\"><td>$row[1]</td>\n
        <td>$row[2].$row[3].$row[4].$row[5]</td>\n
        <td>$row[6]</td>\n
        <td>$row[7]</td>\n
        <td>$row[0]</td>\n";
    }
  }
  else {
    print "<tr><th colspan=5 align=center>Nothing there!</th></tr>\n";
  }
  pg_freeresult($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="icmp"><HR></a>
<?php
 $Selstr="SELECT event.signature,event.timestamp,iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,icmphdr.type,icmphdr.code FROM event,iphdr,icmphdr WHERE iphdr.sid = event.sid AND iphdr.cid = event.cid AND icmphdr.sid = iphdr.sid AND icmphdr.cid = iphdr.cid ORDER BY event.timestamp DESC LIMIT 10;";
 $Result=pg_exec($pg_connection,$Selstr); 

?>
<TABLE BORDER="2" CELLPADDING="5">
    <TR BGCOLOR="#CCCCCC"><TH COLSPAN="5" ALIGN="center">10 most recent ICMP probe reports</B></TH></TR>
    <TR BGCOLOR="#CCCCCC"><TD>Timestamp</TD><TD>Source IP</TD><TD>Type</TD><TD>Code</TD><TD>Signature</TD>
<?php
  if (pg_NumRows($Result) != 0) {
    for ($i = 0; $i < pg_NumRows($Result); $i++ ) {
      $row = pg_fetch_row($Result,$i);
    print "<tr bgcolor=\"white\"><td>$row[1]</td>\n
        <td>$row[2].$row[3].$row[4].$row[5]</td>\n
        <td>$row[6]</td>\n
        <td>$row[7]</td>\n
        <td>$row[0]</td>\n";
    }
  }
  else {
    print "<tr><th colspan=5 align=center>Nothing there!</th></tr>\n";
  }
  pg_freeresult($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="by_signature"><HR></a>
<?php
  $Selstr="SELECT signature,COUNT(cid) as tot_id ,MAX(timestamp) FROM event GROUP BY signature ORDER BY tot_id DESC LIMIT 30";
  $Result=pg_exec($pg_connection,$Selstr);
?>
<TABLE BORDER=2 CELLPADDING="5">
  <TR ROWSPAN="2" BGCOLOR="#CCCCCC"><TH COLSPAN="3" ALIGN="center"># of Reports on each signature</TH></TR>
  <TR BGCOLOR="#CCCCCC"><TD>Numbers</TD><TD ALIGN="center">Signature</TD><TD>Latest Timestamp</TD></TR>
<?php
  if (pg_NumRows($Result) != 0) {
    for ($i = 0; $i < pg_NumRows($Result); $i++ ) {
      $row = pg_fetch_row($Result,$i);
      print "<tr bgcolor=\"white\"><td>$row[1]</td>\n
             <td>$row[0]</td>\n
             <td>$row[2]</td></tr>";
    }
  }
  else {
    print "<tr><th colspan=3 align=center>Nothing there!</th></tr>\n"; 
  }
  pg_freeresult($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="source_sig"><HR></a>
<?php
  $Selstr="SELECT iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,COUNT(iphdr.cid) as total,event.signature,MAX(event.timestamp), MIN(event.timestamp), AGE(MAX(event.timestamp), MIN(event.timestamp)) FROM iphdr,event WHERE event.sid = iphdr.sid AND event.cid = iphdr.cid GROUP BY iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,event.signature ORDER BY total DESC LIMIT 30";
  $Result = pg_exec($pg_connection,$Selstr);
?>
<TABLE BORDER=2 CELLPADDING="5">
  <TR ROWSPAN="2" BGCOLOR="#CCCCCC"><TH COLSPAN="6" ALIGN="center">From the same source IP with the same signature</TH></TR>
  <TR BGCOLOR="$CCCCCC"><TD>Reports</TD><TD>Source IP</TD><TD>Signature</TD><TD>Frequency</TD><TD>First Timestamp</TD><TD>Latest Timestamp</TD></TR>
<?
  if (pg_NumRows($Result) !=0 ) {
    for ($i = 0; $i < pg_NumRows($Result); $i++ ) {
      $row = pg_fetch_row($Result,$i);
      $freq = turn_sec($row[8]) / $row[4];
      print "<tr bgcolor=\"white\"><td>$row[4]</td>\n
             <td>$row[0].$row[1].$row[2].$row[3]</td>\n
             <td>$row[5]</td>\n
             <td>Once every $freq seconds</td>\n
             <td>$row[7]</td>\n
             <td>$row[6]</td>\n";
    }
  }
  else {
    print "<tr><th colspan=6 align=center>Nothing there!</th></tr>\n";
  }
  pg_freeresult($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="yourip"><HR></a>
<?php
  $ip1='128';$ip2='2';$ip3='104';$ip4='107'; /* Change this to the IP you want to watch! */
  $Selstr="SELECT event.signature,MIN(event.timestamp),MAX(event.timestamp),iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,COUNT(iphdr.cid) as total, AGE(MAX(event.timestamp), MIN(event.timestamp)) FROM event,iphdr WHERE iphdr.ip_dst0 = $ip1 AND iphdr.ip_dst1 = $ip2 AND iphdr.ip_dst2 = $ip3 AND iphdr.ip_dst3 = $ip4 AND event.sid = iphdr.sid AND event.cid=iphdr.cid GROUP BY iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,event.signature ORDER BY total DESC LIMIT 30";
 $Result=pg_exec($pg_connection,$Selstr); 
?>
<TABLE BORDER=2 CELLPADDING="5">
  <TR ROWSPAN="2" BGCOLOR="#CCCCCC"><TH COLSPAN="6" ALIGN="center"> SCANS to the specified IP (xanadu.rem.cmu.edu)</TH></TR>
  <TR BGCOLOR="#CCCCCC"><TD>Reports</TD><TD ALIGN="center">started at</TD><TD>source IP</TD><TD>last recorded timestamp</TD><TD>Signature</TD><TD>Frequency</TD></TR>
    
<?php

  if (pg_NumRows($Result) != 0) {
    for ($i = 0; $i < pg_NumRows($Result); $i++ ) {
      $row = pg_fetch_row($Result,$i);
    if ($row[7] != 0) 
      $freq = turn_sec($row[8]) / $row[7];
    print "<tr bgcolor=\"white\"><td>$row[7]</td>\n
        <td>$row[1]</td>\n
        <td>$row[3].$row[4].$row[5].$row[6]</td>\n
        <td>$row[2]</td>\n
        <td>$row[0]</td>\n
        <td>Once every $freq seconds\n";
    }
  }
  else {
    print "<tr><th colspan=5 align=center>Nothing there!</th></tr>\n";
  }

?>
</TABLE>
<a href="#top">Top</a>
<?php
pg_close($pg_connection);
?>
    <hr>
    <address><a href="mailto:chenym@CMU.EDU">Yen-Ming Chen</a></address>
<!-- Created: Fri Feb 25 10:15:02 EST 2000 -->
<!-- hhmts start -->
Last modified: $Date: 2000/08/07 02:42:53 $
<!-- hhmts end -->
  </body>
</html>

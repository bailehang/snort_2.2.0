<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<html>
  <head>
    <title>Snort Statistics On-Line</title>
<!-- Html Comments begin here
THIS IS THE MYSQL VERSION OF THE SCRIPT MENTIONED BELOW. IT WORKS IN THE SAME WAY, BUT WITH AN MYSQL DATABASE INSTEAD.
Thomas Linden <tom@daemon.de> 16.04.2000

This is Snort Statistics On-Line PHP script. You need to have php with support of postgresql database. Then just put this file under the directory you allow php to be executed, or name it as foobar.php3. It looks more like http://www.incident.org/ now, but I hope to make it more 'interactive' in the future, or at least do something like my snort_stat.pl does. :)

$Id: mysql.php3,v 1.1.1.1 2000/08/07 02:42:53 roesch Exp $
Yen-Ming Chen <chenym@CMU.EDU>

$Log: mysql.php3,v $
Revision 1.1.1.1  2000/08/07 02:42:53  roesch
Initial Import


Revision 1.1  2000/05/02 01:55:11  yenming
Based on the snort statistic php3 script for postgresql
Changed from the contribution of Thomas Linden <tom@daemon.de>
16.04.2000


-->
  </head>

  <body>
    <h1>Snort Statistics On-Line</h1>

<?php
  $ip1='128';
  $ip2='2';
  $ip3='84';
  $ip4='43';  /* Change this to the IP you want to watch! */
  /* The parameters here assume you use MySQL on localhost, and run this php 
     script as a valid user to access the database */
 $db_host 	= "localhost";
 $db_user 	= "nobody";
 $db_passwd 	= "";
 $db_database 	= "snort";
 $db_connection = mysql_connect($db_host, $db_user, $db_passwd);  
 mysql_select_db($db_database);
?>

<h2>Summary</h2>
<?php
  $Selstr="SELECT COUNT(event.cid),MIN(event.timestamp),MAX(event.timestamp) FROM event";
  $Selstr2="SELECT DISTINCT signature FROM event";
  $Selstr3="SELECT ip_src0,ip_src1,ip_src2,ip_src3 FROM iphdr GROUP BY ip_src0,ip_src1,ip_src2,ip_src3";
  $Selstr4="SELECT ip_dst0,ip_dst1,ip_dst2,ip_dst3 FROM iphdr GROUP BY ip_dst0,ip_dst1,ip_dst2,ip_dst3";
  $Result =mysql_query($Selstr, $db_connection);
  $Result2=mysql_query($Selstr2, $db_connection);
  $Result3=mysql_query($Selstr3, $db_connection);
  $Result4=mysql_query($Selstr4, $db_connection);

  if($Result2 != 0) {
  	if(mysql_num_rows($Result2) != 0) { 
		$tot_sig = mysql_num_rows($Result2);
	  } 
	  else {
		$tot_sig = 0;
	  }
  }

  if($Result3 != 0) {
  	if(mysql_num_rows($Result3) != 0) { 
  	      $tot_dip = mysql_num_rows($Result3);
  	} 
  	else {
  	      $tot_dip = 0;
  	}
  }

  if($Result4 != 0) {
  	if(mysql_num_rows($Result4) != 0) { 
  	      $tot_sip = mysql_num_rows($Result4);
  	} 
  	else {
  	      $tot_sip = 0;
  	}
  }

  if ($Result != 0) {
    $row = mysql_fetch_row($Result);
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
  mysql_free_result($Result);
  mysql_free_result($Result2);
  mysql_free_result($Result3);
  mysql_free_result($Result4);
?>
<HR>
<H2><a name="top">Table Of Contents</a></H2>
    <ul>
      <li><a href="#tcp">10 most recent TCP probes</a></li>
      <li><a href="#udp">10 most recent UDP probes</a></li>
      <li><a href="#icmp">10 most recent ICMP probes</a></li>
      <li><a href="#by_signature">Reports by signatures</a></li>
      <li><a href="#source_sig">From same source with same signature</a></li>
      <li><a href="#yourip">Scans to specified host</a></li>
    </ul>
<a name="tcp"><HR></a>
<?php
 $Selstr="SELECT event.signature,event.timestamp,iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,tcphdr.th_sport,tcphdr.th_dport FROM event,iphdr,tcphdr WHERE iphdr.sid = event.sid and iphdr.cid = event.cid and tcphdr.cid = event.cid ORDER BY event.timestamp DESC LIMIT 10";
 $Result=mysql_query($Selstr, $db_connection); 

?>
<TABLE BORDER="2" CELLPADDING="5">
    <TR BGCOLOR="#CCCCCC"><TH COLSPAN="5" ALIGN="center">10 most recent TCP probe reports</B></TH></TR>
    <TR BGCOLOR="#CCCCCC"><TD>Timestamp</TD><TD>Source IP</TD><TD>Source Port</TD><TD>Dest Port</TD><TD>Signature</TD>
<?php
  if (mysql_num_rows($Result) != 0) {
    for ($i = 0; $i < mysql_num_rows($Result); $i++ ) {
      $row = mysql_fetch_row($Result);
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
  mysql_free_result($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="udp"><HR></a>
<?php
 $Selstr="SELECT event.signature,event.timestamp,iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,udphdr.uh_sport,udphdr.uh_dport FROM event,iphdr,udphdr WHERE iphdr.sid = event.sid AND iphdr.cid = event.cid AND udphdr.sid = iphdr.sid AND udphdr.cid = iphdr.cid ORDER BY event.timestamp DESC LIMIT 10;";
 $Result=mysql_query($Selstr, $db_connection); 
?>
<TABLE BORDER="2" CELLPADDING="5">
    <TR BGCOLOR="#CCCCCC"><TH COLSPAN="5" ALIGN="center">10 most recent UDP probe reports</B></TH></TR>
    <TR BGCOLOR="#CCCCCC"><TD>Timestamp</TD><TD>Source IP</TD><TD>Source Port</TD><TD>Dest Port</TD><TD>Signature</TD>
<?php
  if (mysql_num_rows($Result) != 0) {
    for ($i = 0; $i < mysql_num_rows($Result); $i++ ) {
      $row = mysql_fetch_row($Result);
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
  mysql_free_result($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="icmp"><HR></a>
<?php
 $Selstr="SELECT event.signature,event.timestamp,iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,icmphdr.type,icmphdr.code FROM event,iphdr,icmphdr WHERE iphdr.sid = event.sid AND iphdr.cid = event.cid AND icmphdr.sid = iphdr.sid AND icmphdr.cid = iphdr.cid ORDER BY event.timestamp DESC LIMIT 10";
 $Result=mysql_query($Selstr, $db_connection); 

?>
<TABLE BORDER="2" CELLPADDING="5">
    <TR BGCOLOR="#CCCCCC"><TH COLSPAN="5" ALIGN="center">10 most recent ICMP probe reports</B></TH></TR>
    <TR BGCOLOR="#CCCCCC"><TD>Timestamp</TD><TD>Source IP</TD><TD>Type</TD><TD>Code</TD><TD>Signature</TD>
<?php
  if (mysql_num_rows($Result) != 0) {
    for ($i = 0; $i < mysql_num_rows($Result); $i++ ) {
      $row = mysql_fetch_row($Result);
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
  mysql_free_result($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="by_signature"><HR></a>
<?php
  $Selstr="SELECT signature,COUNT(cid) as tot_id ,MAX(timestamp) FROM event GROUP BY signature ORDER BY tot_id DESC LIMIT 30";
  $Result=mysql_query($Selstr, $db_connection);
?>
<TABLE BORDER=2 CELLPADDING="5">
  <TR ROWSPAN="2" BGCOLOR="#CCCCCC"><TH COLSPAN="3" ALIGN="center"># of Reports on each signature</TH></TR>
  <TR BGCOLOR="#CCCCCC"><TD>Numbers</TD><TD ALIGN="center">Signature</TD><TD>Latest Timestamp</TD></TR>
<?php
  if ($Result != 0) {
    for ($i = 0; $i < mysql_num_rows($Result); $i++ ) {
      $row = mysql_fetch_row($Result);
      print "<tr bgcolor=\"white\"><td>$row[1]</td>\n
             <td>$row[0]</td>\n
             <td>$row[2]</td></tr>";
    }
  }
  else {
    print "<tr><th colspan=3 align=center>Nothing there!</th></tr>\n"; 
  }
  mysql_free_result($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="source_sig"><HR></a>
<?php
  $Selstr="SELECT iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,COUNT(iphdr.cid) as total,event.signature,MAX(event.timestamp), MIN(event.timestamp), UNIX_TIMESTAMP(MAX(event.timestamp)) - UNIX_TIMESTAMP(MIN(event.timestamp)) FROM iphdr,event WHERE event.sid = iphdr.sid AND event.cid = iphdr.cid GROUP BY iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,event.signature ORDER BY total DESC LIMIT 30";
  $Result = mysql_query($Selstr, $db_connection);
?>
<TABLE BORDER=2 CELLPADDING="5">
  <TR ROWSPAN="2" BGCOLOR="#CCCCCC"><TH COLSPAN="6" ALIGN="center">From the same source IP with the same signature</TH></TR>
<TR BGCOLOR="$CCCCCC"><TD>Reports</TD><TD>Source IP</TD><TD>Signature</TD><TD>Frequency</TD><TD>First Timestamp</TD><TD>Latest Timestamp</TD></TR>
<?
  if ($Result !=0 ) {
    for ($i = 0; $i < mysql_num_rows($Result); $i++ ) {
      $row = mysql_fetch_row($Result);
      $freq = $row[8] / $row[4];
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
  mysql_free_result($Result);
?>
</TABLE>
<a href="#top">Top</a>
<a name="yourip"><HR></a>
<?php
  $Selstr="SELECT event.signature,MIN(event.timestamp),MAX(event.timestamp),iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,COUNT(iphdr.cid) as total, UNIX_TIMESTAMP(MAX(event.timestamp))-UNIX_TIMESTAMP(MIN(event.timestamp)) FROM event,iphdr WHERE iphdr.ip_dst0 = $ip1 AND iphdr.ip_dst1 = $ip2 AND iphdr.ip_dst2 = $ip3 AND iphdr.ip_dst3 = $ip4 AND event.sid = iphdr.sid AND event.cid=iphdr.cid GROUP BY iphdr.ip_src0,iphdr.ip_src1,iphdr.ip_src2,iphdr.ip_src3,event.signature ORDER BY total DESC LIMIT 30";
 $Result=mysql_query($Selstr, $db_connection); 
?>
<TABLE BORDER=2 CELLPADDING="5">
  <TR ROWSPAN="2" BGCOLOR="#CCCCCC"><TH COLSPAN="6" ALIGN="center"> SCANS to the specified IP (not disclosed here)</TH></TR>
  <TR BGCOLOR="#CCCCCC"><TD>Reports</TD><TD ALIGN="center">started at</TD><TD>source IP</TD><TD>last recorded timestamp</TD><TD>Signature</TD><TD>Frequency</TD></TR>
    
<?php
  if ($Result != 0) {
    for ($i = 0; $i < mysql_num_rows($Result); $i++ ) {
      $row = mysql_fetch_row($Result);
      $freq = $row[8] / $row[7];
    print "<tr bgcolor=\"white\"><td>$row[7]</td>\n
        <td>$row[1]</td>\n
        <td>$row[3].$row[4].$row[5].$row[6]</td>\n
        <td>$row[2]</td>\n
        <td>$row[0]</td>\n
        <td>Once every $freq seconds\n";
    }
  }
  else {
    print "<tr><th colspan=6 align=center>Nothing there!</th></tr>\n";
  }
?>
</TABLE>
<a href="#top">Top</a>
<?php
mysql_close($db_connection);
?>

    <hr>
    <address><a href="mailto:chenym@CMU.EDU">Yen-Ming Chen</a></address>
<!-- Created: Fri Feb 25 10:15:02 EST 2000 -->
<!-- hhmts start -->
Last modified: $Date: 2000/08/07 02:42:53 $
<!-- hhmts end -->
  </body>
</html>

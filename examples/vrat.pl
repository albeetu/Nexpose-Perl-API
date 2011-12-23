#!/usr/bin/perl
###############################################################################
#
#  vrat.pl - VRAT is an acronym for Vulnerabililty Regression Analysis Tool
#
###############################################################################

use strict;
use Algorithm::Diff;
use lib '/home/atu/r7/v4/nexpose/src/internal/private/perlapi/';
use Rapid7Utils::NeXposeAPI;
use Getopt::Long;
use XML::DOM;
use XML::Simple;

use constant SUCCESS => 0;
use constant INVALID_ARGS => 1;
use constant LESS_THAN_2_SCANS => 2;
use constant SCAN_RUNNING => 3;
use constant REPORT_GEN_FAILED => 4;
use constant SCAN_RUNNING_OR_FAILED => 5;
use constant FILE_NOT_FOUND => 6;


&main;
exit (SUCCESS);

sub printHelp
{
   print STDERR <<'HELP';

rat.pl(1)

   NAME:
      vrat.pl - compares the report data from two XML Exports (raw-xml format) 
      returning a list of NeXpose nodes that are Dead, New, and Active. The 
      Active nodes are diffed.

   USAGE:
      $ perl vrat.pl --file1 <file1> --file2 <file2>
      $ perl vrat.pl --host1 <hostname> --uid1 <username> --password1 <password> --site <site ID>
      $ perl vrat.pl --host1 <hostname> --uid1 <username> --password1 <password> --scan1 <scan1 ID> --scan2 <scan2 ID>
      $ perl vrat.pl --host1 <hostname> --uid1 <username> --password1 <password> --scan1 <scan1 ID> 
                     --host2 <hostname> --uid2 <username> --password2 <password> --scan2 <scan2 ID>
      $ perl vrat.pl --file1 <file1> --host2 <hostname> --uid2 <username> --password2 <password> --scan2 <scan2 ID>
      $ perl vrat.pl --file2 <file2> --host1 <hostname> --uid1 <username> --password1 <password> --scan1 <scan1 ID>

   OPTIONS:
      --file1
             The filename of the first scan to compare.

      --file2
             The filename of the second scan to compare.

      --host1
             The first machine hosting NeXpose. This can be an IP address or a hostname,
             as long as the name resolves to an IP it will work.

      --host2
             The second machine hosting NeXpose. This can be an IP address or a hostname,
             as long as the name resolves to an IP it will work.

      --uid1
             The first NeXpose user can be a NeXpose admin or non-admin user.

      --uid2
             The second NeXpose user can be a NeXpose admin or non-admin user.

      --password1
             The first NeXpose users' password.

      --password2
             The second NeXpose users' password.

      --site 
             The site ID in integer format.

      --scan1
             The scan ID of the first scan to compare.

      --scan2
             The scan ID of the second scan to compare.

   If no arguments or the wrong set of arguments are passed in then this help file
   is printed.

   DESCRIPTION:

   The following PERL modules are required to run the script:
      - Algorithm::Diff;
      - Rapid7Utils::NeXposeAPI;
      - Getopt::Long;
      - XML::DOM;
      - XML::Simple;

   The script takes two XML Export files from NeXpose and creates a diff based 
   on the differences between the "test" elements and the operating system 
   "fingerprints" for each device. The key to performing the "test" diff
   is sorting the XML by node and then by the "test" ID. There are five ways
   to call the program: (1) specify the two files that contain the raw XML
   Exports, (2) specify a host running NeXpose, a site with login credentials 
   and use the NeXpose API to create a report for the last two scans of the 
   site, (3) specify a host running NeXpose, login credentials, and the two 
   scan IDs, which are to be diffed. The scan ID's can apply to different sites
   or for the same site, (4) specify two hosts running NeXpose, login credentials,
   and scan ID's for the two hosts, (5) specify a file and a host running
   NeXpose, login credentials, and a scan ID. The output is returned via STDOUT
   and is similar in format to the UNIX "diff" command.

   EXAMPLES:

      $perl vrat.pl --file1 report_20070827.xml --file2 report_20070830.xml
      $perl vrat.pl --host1 10.2.46.250 --uid1 nxadmin --password1 nxadmin --site 2
      $perl vrat.pl --host1 realappliance --uid1 nxadmin --password1 nxadmin --scan1 15
                    --host2 localhost --uid2 'test user' --password2 5ecuR3 p4s5w0rd --scan2 74
      $perl vrat.pl --file2 report_20080122.xml --host1 toaster --uid1 nxadmin --password1 nxadmin --scan1 23

   BUGS:

      None reported yet.

                 September 13, 2007     vrat.pl(1)
HELP
}

sub main
{
   #Load node data into a hash with IP => node_data.
   my %data1;
   my %data2;
   my %deviceList1;
   my %deviceList2;
   my $device_IP;
   my $file_name1;
   my $file_name2;
   my $diff_header;

   #Two arguments specify the two files to diff. Four arguments specify the 
   #host to connect, the username, the user's password, and the site ID to 
   #diff. Five arguments specify host, username, user password, scan1's ID,
   #and scan2's ID. Eight arguments should specify the host, username, password,
   #and scan ID for the two respective scans to compare.
   my $host1;
   my $host2;
   my $username1;
   my $username2;
   my $password1;
   my $password2;
   my $site;
   my $file1;
   my $file2;
   my $scan1;
   my $scan2;

   GetOptions('file1:s' => \$file1,
              'file2:s' => \$file2,
              'host1:s' => \$host1,
              'host2:s' => \$host2,
              'uid1:s' => \$username1,
              'uid2:s' => \$username2,
              'password1:s' => \$password1,
              'password2:s' => \$password2,
              'site:i' => \$site,
              'scan1:i' => \$scan1,
              'scan2:i' => \$scan2);

   if ($file1 && $file2)
   {
      $file_name1 = $file1;
      $file_name2 = $file2;
      $diff_header = "---$file1\n+++$file2\n";
   }
   elsif ($host1 && $username1 && $password1 && $site)
   {
      my ($sc1, $sc2);
      ($file_name1, $file_name2, $sc1, $sc2) = compareLastTwoScans ($host1, $username1, $password1, $site);
      $diff_header = "---Host: $host1, scan $sc1\n+++Host: $host1, scan $sc2\n";
   }
   elsif ($host1 && $username1 && $password1 && $scan1
       && $host2 && $username2 && $password2 && $scan2)
   {
      ($file_name1, $file_name2) = compareTwoHostsScans
                                   (
                                      $host1, $username1, $password1, $scan1,
                                      $host2, $username2, $password2, $scan2
                                   );
      $diff_header = "---Host: $host1, scan: $scan1\n+++Host: $host2, scan: $scan2\n";
   }
   elsif ($host1 && $username1 && $password1 && $scan1 && $scan2)
   {
      ($file_name1, $file_name2) = compareTwoScans ($host1, $username1, $password1, $scan1, $scan2);
      $diff_header = "---Host: $host1, scan $scan1\n+++Host: $host1, scan $scan2\n";
   }
   elsif ($host1 && $username1 && $password1 && $scan1 && $file2)
   {
      $file_name1 = getScanData($host1, $username1, $password1, $scan1);
      $file_name2 = $file2;
      $diff_header = "---Host: $host1, scan $scan1\n+++$file2\n";
   }
   elsif ($host2 && $username2 && $password2 && $scan2 && $file1)
   {
      $file_name1 = $file1;
      $file_name2 = getScanData($host2, $username2, $password2, $scan2);
      $diff_header = "---$file1\n+++Host: $host2, scan $scan2\n";
   }
   else
   {
      &printHelp;
      exit (INVALID_ARGS);
   }

   unless (-f $file_name1)
   {
      print STDERR "File: $file_name1 could not be found\n";
      exit (FILE_NOT_FOUND);
   }

   unless (-f $file_name2)
   {
      print STDERR "File: $file_name2 could not be found\n";
      exit (FILE_NOT_FOUND);
   }

   print STDERR "\nProcessing FILE1: $file_name1\n";
   &processData ($file_name1, \%data1, \%deviceList1);
   print STDERR "\nProcessing FILE2: $file_name2\n";
   &processData ($file_name2, \%data2, \%deviceList2);

   print STDERR "Printing diff information\n";
   my ($activeDevices, $deadDevices, $newDevices) = &createDeviceList(\%deviceList1,\%deviceList2);

   print $diff_header;

   #List the Dead devices.
   print "=" x 80 . "\n" if @{$deadDevices};
   foreach my $device_IP (@{$deadDevices})
   {
      print "Dead device: $device_IP\n";
   }

   #List the New devices.
   print "=" x 80 . "\n" if @{$newDevices};
   foreach my $device_IP (@{$newDevices})
   {
      print "New device: $device_IP\n";
   }

   #Find the differences for the Active Devices.
   foreach my $device_IP (@{$activeDevices})
   {
      print "=" x 80 . "\nDiffing device: $device_IP\n";
      &diffDevices ($data1{$device_IP}, $data2{$device_IP});
   }
}

sub compareLastTwoScans
{
   my $host = shift;
   my $username = shift;
   my $password = shift;
   my $site = shift;
   my @filter;
   my $scan1;
   my $scan2;

   my $napi = new Rapid7Utils::NeXposeAPI ("host" => "$host", "sync-id" => "1");
   print STDERR $napi->login ("user-id" => "$username", "password" => "$password");
   print STDERR "Connecting to: $napi->{'host'}\n\n";

   #Get the scan info for the site
   my %SSout = %{XMLin ($napi->siteScanHistory ("site-id" => $site), ForceArray => 1, KeyAttr => [])};

   #Verify there at least two scans to diff (assumes sequential order of scan data)
   if (exists ($SSout{'ScanSummary'}[-1]) && exists ($SSout{'ScanSummary'}[-2]))
   {
      #Make sure that a scan isn't running for the newest scan
      if ($SSout{'ScanSummary'}[-1]{'status'} eq 'finished')
      {
         #scan1 is the second to last element in the ScanSummary array hence the earlier scan
         $scan1 = $SSout{'ScanSummary'}[-2]{'scan-id'};
         $scan2 = $SSout{'ScanSummary'}[-1]{'scan-id'};

         @filter = ({"id" => "$scan1", "type" => "scan"});
         my $uri1 = createReport ($napi,\@filter);
         #Remove carriage returns for windows based operating systems
         my $temp = $napi->getURI ("uri" => $uri1)->content;
         $temp =~ s/\r//g;
         
         #set the filter to the scan ID of the newest scan before creating the next report
         $filter[0]{'id'} = $scan2;
         my $uri2 = createReport ($napi,\@filter);

         open (SCAN1, ">report_scan1.xml") or die ("Could not open file!");
         print SCAN1 $temp;
         close SCAN1;

         $temp = $napi->getURI ("uri" => $uri2)->content;
         $temp =~ s/\r//g;

         open (SCAN2, ">report_scan2.xml") or die ("Could not open file!");
         print SCAN2 $temp;
         close SCAN2;
      }
      else
      {
         print STDERR "A scan is still running for this site\n";
         exit (SCAN_RUNNING);
      }
   }
   else
   {
      print STDERR "The site needs at least two scans to perform a diff\n";
      exit(LESS_THAN_2_SCANS);
   }

   print STDERR $napi->logout();

   return ("report_scan1.xml", "report_scan2.xml", $scan1, $scan2);
}

sub compareTwoScans
{
   my $host = shift;
   my $username = shift;
   my $password = shift;
   my $scan1 = shift;
   my $scan2 = shift;
   my @filter;

   my $napi = new Rapid7Utils::NeXposeAPI ("host" => "$host", "sync-id" => "1");
   print STDERR $napi->login ("user-id" => "$username", "password" => "$password");
   print STDERR "Connecting to: $napi->{'host'}\n\n";

   #Get the scan info
   my %SS1out = %{XMLin ($napi->scanStatus ("scan-id" => $scan1), ForceArray => 1, KeyAttr => [])};
   my %SS2out = %{XMLin ($napi->scanStatus ("scan-id" => $scan2), ForceArray => 1, KeyAttr => [])};

   #Verify the scans are not currently running nor have failed.
   if ($SS1out{'status'} ne 'running' && $SS1out{'status'} ne 'failed')
   {
      print STDERR "Scan1 exists\n";
      #The scan status is finished or stopped, so it's safe to create the report
      my $scan = $SS1out{'scan-id'};
      @filter = ({"id" => "$scan", "type" => "scan"});
      my $uri = createReport ($napi,\@filter);
      #Remove carriage returns for windows based operating systems
      my $temp = $napi->getURI ("uri" => $uri)->content;
      $temp =~ s/\r//g;

      open (SCAN1, ">report_scan1.xml") or die ("Could not open file!");
      print SCAN1 $temp;
      close SCAN1;
   }
   else
   {
      print STDERR "A scan is still running or has failed\n";
      exit (SCAN_RUNNING_OR_FAILED);
   }

   if ($SS2out{'status'} ne 'running' && $SS2out{'status'} ne 'failed')
   {
      print STDERR "Scan2 exists\n";
      #The scan status is finished or stopped, so it's safe to create the report
      my $scan = $SS2out{'scan-id'};
      @filter = ({"id" => "$scan", "type" => "scan"});
      my $uri = createReport ($napi,\@filter);
      #Remove carriage returns for windows based operating systems
      my $temp = $napi->getURI ("uri" => $uri)->content;
      $temp =~ s/\r//g;

      open (SCAN2, ">report_scan2.xml") or die ("Could not open file!");
      print SCAN2 $temp;
      close SCAN2;
   }
   else
   {
      print STDERR "A scan is still running or has failed\n";
      exit (SCAN_RUNNING_OR_FAILED);
   }

   print STDERR $napi->logout();

   return ("report_scan1.xml", "report_scan2.xml");
}

sub compareTwoHostsScans
{
   my $host1 = shift;
   my $username1 = shift;
   my $password1 = shift;
   my $scan1 = shift;
   my $host2 = shift;
   my $username2 = shift;
   my $password2 = shift;
   my $scan2 = shift;

   my $napi1 = new Rapid7Utils::NeXposeAPI ("host" => "$host1", "sync-id" => "1");
   my $napi2 = new Rapid7Utils::NeXposeAPI ("host" => "$host2", "sync-id" => "2");
   print STDERR $napi1->login ("user-id" => "$username1", "password" => "$password1");
   print STDERR "Connecting to: $napi1->{'host'}\n\n";
   print STDERR $napi2->login ("user-id" => "$username2", "password" => "$password2");
   print STDERR "Connecting to: $napi2->{'host'}\n\n";

   #Get the scan info
   my %SS1out = %{XMLin ($napi1->scanStatus ("scan-id" => $scan1), ForceArray => 1, KeyAttr => [])};
   my %SS2out = %{XMLin ($napi2->scanStatus ("scan-id" => $scan2), ForceArray => 1, KeyAttr => [])};

   #Verify the scans are not currently running nor have failed.
   if ($SS1out{'status'} ne 'running' && $SS1out{'status'} ne 'failed')
   {
      print STDERR "Scan1 exists\n";
      #The scan status is finished or stopped, so it's safe to create the report
      my $scan = $SS1out{'scan-id'};
      my @filter = ({"id" => "$scan", "type" => "scan"});
      my $uri = createReport ($napi1,\@filter);
      #Remove carriage returns for windows based operating systems
      my $temp = $napi1->getURI ("uri" => $uri)->content;
      $temp =~ s/\r//g;

      open (SCAN1, ">report_scan1.xml") or die ("Could not open file!");
      binmode SCAN1;
      print SCAN1 $temp;
      close SCAN1;
   }
   else
   {
      print STDERR "A scan is still running or has failed\n";
      exit (SCAN_RUNNING_OR_FAILED);
   }

   if ($SS2out{'status'} ne 'running' && $SS2out{'status'} ne 'failed')
   {
      print STDERR "Scan2 exists\n";
      #The scan status is finished or stopped, so it's safe to create the report
      my $scan = $SS2out{'scan-id'};
      my @filter = ({"id" => "$scan", "type" => "scan"});
      my $uri = createReport ($napi2,\@filter);
      #Remove carriage returns for windows based operating systems
      my $temp = $napi2->getURI ("uri" => $uri)->content;
      $temp =~ s/\r//g;

      open (SCAN2, ">report_scan2.xml") or die ("Could not open file!");
      binmode SCAN2;
      print SCAN2 $temp;
      close SCAN2;
   }
   else
   {
      print STDERR "A scan is still running or has failed\n";
      exit (SCAN_RUNNING_OR_FAILED);
   }

   print STDERR $napi1->logout();
   print STDERR $napi2->logout();

   return ("report_scan1.xml", "report_scan2.xml");
}

sub getScanData
{
   my $host = shift;
   my $username = shift;
   my $password = shift;
   my $scan = shift;
   my @filter;

   my $napi = new Rapid7Utils::NeXposeAPI ("host" => "$host", "sync-id" => "1");
   print STDERR $napi->login ("user-id" => "$username", "password" => "$password");
   print STDERR "Connecting to: $napi->{'host'}\n\n";

   #Get the scan info
   my %SSout = %{XMLin ($napi->scanStatus ("scan-id" => $scan), ForceArray => 1, KeyAttr => [])};

   #Verify the scan is currently not running nor has failed.
   if ($SSout{'status'} ne 'running' && $SSout{'status'} ne 'failed')
   {
      print STDERR "Scan exists\n";
      #The scan status is finished or stopped, so it's safe to create the report
      my $scan = $SSout{'scan-id'};
      @filter = ({"id" => "$scan", "type" => "scan"});
      my $uri = createReport ($napi,\@filter);
      #Remove carriage returns for windows based operating systems
      my $temp = $napi->getURI ("uri" => $uri)->content;
      $temp =~ s/\r//g;

      print STDERR "Saving the raw XML export to a file named \"report_scan2.xml\"\n";
      open (SCAN, ">report_scan2.xml") or die ("Could not open file!");
      binmode SCAN2;
      print SCAN $temp;
      close SCAN;
   }
   else
   {
      print STDERR "A scan is still running or has failed\n";
      exit (SCAN_RUNNING_OR_FAILED);
   }

   print STDERR $napi->logout();

   return ("report_scan2.xml");
}


##############################################################################
# Name: createReport
# Description: This function uses the NeXpose API ReportSaveRequest function
#    to generate the reports. When the report has finished the function
#    returns the URI of the report.
# Notes: The template-id and the compareTo fields are not necessary here.
#    The XML Export does not need these values but they are required as stated
#    by the API Document.
##############################################################################
sub createReport
{
   my $napi = shift;
   my $filter = shift;
   my %RSout;
   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
   my $create_time = sprintf "%4d-%02d-%02d %02d:%02d:%02d",$year+1900,$mon+1,$mday,$hour,$min,$sec;

   print STDERR "Creating report: [$create_time] raw-xml\n";
   %RSout = %{XMLin($napi->reportSave( "id" => "-1", 
                                       "name" => "[$create_time]: raw-xml", 
                                       "template-id" => "garbage",
                                       "format" => "raw-xml",
                                       "Filters" => $filter,
                                       "compareTo" => "20061131T00000000",
                                       "after-scan" => "0",
                                     ), ForceArray => 1, KeyAttr => [] 
                   )
             };
   while(XMLin($napi->reportHistory("reportcfg-id"=>$RSout{'reportcfg-id'}))->{'ReportSummary'}{'status'} ne "Generated" ||
         XMLin($napi->reportHistory("reportcfg-id"=>$RSout{'reportcfg-id'}))->{'ReportSummary'}{'status'} eq "Started")
   {
      #check for 'failed' status so it doesn't loop forever.
      if(XMLin($napi->reportHistory("reportcfg-id"=>$RSout{'reportcfg-id'}))->{'ReportSummary'}{'status'} eq "Failed" ||
         XMLin($napi->reportHistory("reportcfg-id"=>$RSout{'reportcfg-id'}))->{'ReportSummary'}{'status'} eq "Aborted" ||
         XMLin($napi->reportHistory("reportcfg-id"=>$RSout{'reportcfg-id'}))->{'ReportSummary'}{'status'} eq "Unknown")
      {
         exit (REPORT_GEN_FAILED);
      }
      sleep(1);
   }
   #Always sleep for 1 second so that reports don't get created with the same name
   sleep(1);
   return XMLin($napi->reportHistory("reportcfg-id"=>$RSout{'reportcfg-id'}))->{'ReportSummary'}{'report-URI'};
}

sub processData
{
   my $input_file = shift;
   my $data = shift;
   my $deviceList = shift;
   my $device_IP;
   my %test_hash;

   my $parser = new XML::DOM::Parser;
   my $doc = $parser->parsefile ($input_file);
   my $device_nodes = $doc->getElementsByTagName ("node");
my $count = 0;
   for (my $i = 0; $i < $device_nodes->getLength; $i++)
   {
      my $node = $device_nodes->item ($i);
      my $node_attr = $node->getAttributes();
      for (my $n = 0; $n < $node_attr->getLength; $n++)
      {
         if ($node_attr->item($n)->getName eq 'address')
         {
            $device_IP = $node_attr->item($n)->getValue;
            #Gather all device nodes
            $$deviceList{$device_IP} = "";
         }
      }

      #Gather the device fingerprints and store the data by certainty and/or 
      #version number if it exists.
      my $fingerprints = $node->getElementsByTagName ("fingerprints");
      for (my $f = 0; $f < $fingerprints->getLength; $f++)
      {
         my $os_fp= $fingerprints->item ($f);
         my $os = $os_fp->getElementsByTagName ("os");
         
         for (my $o = 0; $o < $os->getLength; $o++)
         {
            my $one_os = $os->item($o);
            unless (UNIVERSAL::isa($one_os, "XML::DOM::Text"))
            {
               my $certainty;
               my $vendor;
               my $family;
               my $product;
               my $version;
               my $os_attr = $one_os->getAttributes;

               #Get the fingerprint attributes
               for (my $g = 0; $g < $os_attr->getLength; $g++)
               {
                  if ($os_attr->item($g)->getNodeName eq "certainty")
                  {
                     $certainty = $os_attr->item($g)->getValue;
                  }
                  elsif ($os_attr->item($g)->getNodeName eq "vendor")
                  {
                     $vendor = $os_attr->item($g)->getValue;
                  }
                  elsif ($os_attr->item($g)->getNodeName eq "family")
                  {
                     $family = $os_attr->item($g)->getValue;
                  }
                  elsif ($os_attr->item($g)->getNodeName eq "product")
                  {
                     $product = $os_attr->item($g)->getValue;
                  }
                  elsif ($os_attr->item($g)->getNodeName eq "version")
                  {
                     $version = $os_attr->item($g)->getValue;
                  }
               }
               my $fp_data = "<fingerprint ";
               $fp_data .= "certainty =\"$certainty\" " if $certainty;
               $fp_data .= "vendor=\"$vendor\" " if $vendor;
               $fp_data .= "family=\"$family\" " if $family;
               $fp_data .= "product=\"$product\" " if $product;
               $fp_data .= "version=\"$version\" />" if $version;
               $version = "0" unless $version;
               push (@{$test_hash{$device_IP}{'fingerprints'}{$certainty}{$version}}, $fp_data);
            }
         }
      }

      #Gather all of the test elements and necessary test attributes.
      my $tests = $node->getElementsByTagName ("tests");
      for (my $j = 0; $j < $tests->getLength; $j++)
      {
         my $test = $tests->item ($j);
         my $one_test = $test->getElementsByTagName ("test");
         for (my $k = 0; $k < $one_test->getLength; $k++ )
         {
            my $blob = $one_test->item($k);
            $count++;
            unless (UNIVERSAL::isa($blob, "XML::DOM::Text"))
            {
               my $id;
               my $status;
               my $attr = $blob->getAttributes;
               for (my $m = 0; $m < $attr->getLength; $m++)
               {
                  if ($attr->item($m)->getNodeName eq "id")
                  {
                     $id = $attr->item($m)->getValue;
                  }
                  elsif ($attr->item($m)->getNodeName eq "status")
                  {
                     $status = $attr->item($m)->getValue;
                  }
               }
               push (@{$test_hash{$device_IP}{'tests'}{$id}{$status}}, "<test status =\"$status\" id=\"$id\" />");
            }
         }
      }
   }

   #Go through the Hash of Hash of Arrays and order the device fingerprints 
   #and test data.
   foreach my $device (keys %test_hash)
   {
      foreach my $cert (sort keys %{$test_hash{$device}{'fingerprints'}})
      {
         foreach my $ver (sort keys %{$test_hash{$device}{'fingerprints'}{$cert}})
         {
            foreach my $fp (@{$test_hash{$device}{'fingerprints'}{$cert}{$ver}})
            {
               push (@{$$data{$device}}, $fp . "\n");
            }
         }
      }
      foreach my $id (sort keys %{$test_hash{$device}{'tests'}})
      {
         foreach my $status (sort keys %{$test_hash{$device}{'tests'}{$id}})
         {
            foreach my $test (@{$test_hash{$device}{'tests'}{$id}{$status}})
            {
               $test .= "\n" if $test !~ /\n$/;
               push (@{$$data{$device}}, $test);
            }
         }
      }
   }
print STDERR "Number of tests: $count\n";

}

sub createDeviceList
{
   my $deviceList1 = shift;
   my $deviceList2 = shift;
   my @deadDevices;
   my @activeDevices;
   my @newDevices;

   foreach my $device1 (sort keys %{$deviceList1})
   {
      if (defined ($$deviceList2{$device1}))
      {
         #device1 found in deviceList2. Now we compare all of the node data.
         #print "Device $device1 is active\n";
         push (@activeDevices, $device1);
      }
      else
      {
         #node1 not found in deviceList2. Nothing need be done to process this node.
         #print "Device $device1 is DEAD\n";
         push (@deadDevices, $device1);
      }
   }

   foreach my $device2 (sort keys %{$deviceList2})
   {
      if (!defined ($$deviceList1{$device2}))
      {
         #device2 not found in deviceList1. Nothing need be done to process this node.
         #print "Device $device2 is NEW\n";
         push (@newDevices, $device2);
      }
   }
   return (\@activeDevices, \@deadDevices, \@newDevices);
}

#code borrowed from the PERL help for Algorithm::Diff with minor changes 
#printing out output similar to the UNIX diff.
sub diffDevices
{
   my $seq1 = shift;
   my $seq2 = shift;

   my $diff = Algorithm::Diff->new( $seq1, $seq2 );

   $diff->Base( 1 );   # Return line numbers, not indices
   while(  $diff->Next()  ) 
   {
      next   if  $diff->Same();
      my $sep = '';
      if(  ! $diff->Items(2)  ) 
      {
         printf "\n%d,%dd%d\n",
         $diff->Get(qw( Min1 Max1 Max2 ));
      } 
      elsif(  ! $diff->Items(1)  ) 
      {
         printf "\n%da%d,%d\n",
         $diff->Get(qw( Max1 Min2 Max2 ));
      }
      else 
      {
         $sep = "---\n";
         printf "\n%d,%dc%d,%d\n",
         $diff->Get(qw( Min1 Max1 Min2 Max2 ));
      }
      print "- $_"   for  $diff->Items(1);
      print $sep;
      print "+ $_"   for  $diff->Items(2);
   }
}

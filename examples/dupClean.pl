#usr/bin/perl

use strict;
use lib '/home/atu/Nexpose-Perl-API/lib';
use Getopt::Long;
use XML::DOM;
use XML::Simple;
use Data::Dumper;
use Rapid7Utils::NeXposeAPI;

my $napi = new Rapid7Utils::NeXposeAPI ("host" => "localhost", "sync-id" => "1");
#print STDERR $napi->login ("user-id" => "v4test", "password" => "buynexpose");
#print STDERR "Connecting to: $napi->{'host'}\n\n";


#my $ref = XMLin($napi->siteDeviceListing ("site-id" => "2"));
my $ref = XMLin("testxml");
my %device_list =();
my $deleterecord = 0;

foreach my $key (keys %{$ref->{SiteDevices}->{device}})
{
	#print $key." address => ".$ref->{SiteDevices}->{device}->{$key}->{address}."\n";
	my $address = $ref->{SiteDevices}->{device}->{$key}->{address};
	if (exists $device_list{$address})
	{
	# Found an IP match!! Delete record that has lower device ID

		print " ===>$address Exists ===> $device_list{$address}{'device_id'} is proof\n";
		if ($key > $device_list{$address}{'device_id'})
		{
			#Delete the device that has $value
			if ($deleterecord)
			{
				print "==> DELETERECORD IS ON: Deleting device id $device_list{$address}{'device_id'} => $address\n";
				$napi->deviceDelete("device-id" => $device_list{$address}{'device_id'});
			}
			else
			{
				print "===> DELETERECORD IS OFF: Would have deleted device id $device_list{$address}{'device_id'} => $address\n";
			}
			print "==> replace $key as the largest device id\n";
			$device_list{$address}{'device_id'} = $key;
		}
		else
		{
			#leave the record alone
			print "leaving device id $device_list{$address}{'device_id'} => $address\n";
                        if ($deleterecord)
                        {
                                print "==> DELETERECORD IS ON: Deleting device id $key => $address\n";
                                $napi->deviceDelete("device-id" => $key);
                        }
                        else
                        {
                                print "===> DELETERECORD IS OFF: Would have deleted device id $key => $address\n";
                        }
		}	
	}
	else
	{
		# add to the device_list
		print "adding device => $address with deviceID = $key\n";
		$device_list{$address}{'device_id'} = $key;
	}
}
print "**** Device kept*****\n";
print "*********************\n";
print Dumper(%device_list);

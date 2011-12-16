package InputPlugins::NeXpose;

use strict;
use warnings;

BEGIN
{
    use SFCheckPreReq;
    SFCheckPreReq::assertModules(['LWP::UserAgent',
                                  'HTTP::Request',
                                  'HTTP::Response',
                                  'MIME::Base64',
                                  'HTTP::Request::Common',
                                  'Getopt::Long',
                                  'Data::Dumper',
                                  'XML::Simple',
                                  'XML::Twig',
                                  'Net::IP',
                                  'SFHIClient',
                                  'SFHILog',
                                  'YAML::XS',
								  'Digest::MD5',
								  'Number::Range']);
}

use LWP::UserAgent;

use HTTP::Request;
use HTTP::Request::Common;
use HTTP::Response;
use MIME::Base64 ( );

use Getopt::Long;
use Data::Dumper;
use XML::Simple;
use XML::Twig;
use Net::IP;
use SFHIClient;
use SFHILog;
use YAML::XS qw(LoadFile);
use Digest::MD5 qw(md5_hex);
use Number::Range;

use vars qw( $conf );

my $path = '.';
my $vuln_href;

my $useragent = LWP::UserAgent->new();
my $xmlresponse = new XML::Simple;
my $csv_buffer = "SetSource,NeXpose Scan Report\n";

my $host_count = 0;
my $last_addr = '';
my ($userid,$password,$nexposeurl,$sessionid,$siteid,$groupid,$add_host,$hostname_attr,$set_os,$os_attr,$Logger,$keep_xml) = (undef,undef,undef,undef,undef,undef,undef,undef,undef,undef,undef,undef);

# info hash containing plugin information
my $info = {
    init => \&init,
    input => \&input,
    description => "Handles Rapid7 NeXpose Scan Reports",
    info => "<Filename of YAML configuration file defining below parameters>",
    parameters =>
            "\t\t[user_id]: NeXpose Login User ID\n" .
            "\t\t[password]: NeXpose Login Password\n" .
            "\t\t[nexpose_console]: IP address for NeXpose Security Console\n" .
            "\t\t[site_id] (optional): Range of Site IDs to import data for\n" .
			"\t\t[group_id] (optional): Range of Group IDs to import data for\n" .
            "\t\t[add_host] (optional): AddHost will be inserted before AddScanResult if this is set to 'y'\n" .
			"\t\t[set_hostname_attr] (optional): Host attribute to which DNS hostname is assigned\n" .
			"\t\t[set_os_attr] (optional): Host attribute to which operating system is assigned\n"
           };

# called for every plugin at program initialization time
sub register{
    return $info;
}

# called if this plugin is selected.  $opts contains the filename to parse.
sub init{

    my ($opts) = @_;

    if( $opts->{logging} )
    {
        $Logger = $opts->{logging};
    }
    else
    {
        die "No Logging Object Available for plugin NeXpose";
    }

    my $data;
    if( $opts->{plugininfo} )
    {
        $data = LoadFile($opts->{plugininfo});
    }
    elsif( -e 'InputPlugins/NeXpose.yaml' )
    {
        $data = LoadFile('InputPlugins/NeXpose.yaml');
    }
    else
    {
        $Logger->log($SFHILog::ERROR,"<< Cannot Load NeXpose Configuration File >>");
        die "No configuration file available for NeXpose";
    }

    if (defined($data->{user_id}))
    {
        $userid = $data->{user_id};
    }
    else
    {
        die "No value provided for required key : user_id\n";
    }

    if (defined($data->{password}))
    {
        $password = $data->{password};
    }
    else
    {
        die "No value provided for required key : password\n";
    }

    if (defined($data->{nexpose_console}))
    {
        $nexposeurl = 'https://' . $data->{nexpose_console} . ':3780/api/1.1/xml';
    }
    else
    {
        die "No value provided for required key : nexpose_console\n";
    }

	$siteid = $data->{site_id} if defined($data->{site_id});
	$groupid = $data->{group_id} if defined($data->{group_id});
    $keep_xml = $data->{keep_xml} if defined($data->{keep_xml});

    if(defined($data->{add_host}))
    {
        if ( $data->{add_host} =~ /^(?:y|ye|yes|t|true)/i )
        {
            $add_host = 1;
        }
        elsif ( $data->{add_host} =~ /^(?:n|no|f|false)/i )
        {
            $add_host = undef;
        }
        else
        {
            die "Invalid value '".$data->{add_host}."' for key 'add_host' in YAML config\n";
        }
    }

	$hostname_attr = $data->{set_hostname_attr} if defined($data->{set_hostname_attr});
	$os_attr = $data->{set_os_attr} if defined($data->{set_os_attr});

    return 0;
}

sub input
{
	$Logger->log($SFHILog::INFO,"NeXpose Report Processing Starting");
    
	if ($siteid)
	{
		$siteid = parseNumRanges($siteid);
		$Logger->log($SFHILog::INFO,"Site ID: $siteid");
	}
	
	if ($groupid)
	{
		$groupid = parseNumRanges($groupid);
		$Logger->log($SFHILog::INFO,"Group ID: $groupid");
	}

	if (!defined($siteid) && !defined($groupid))
	{
		die "Either site_id or group_id must be specified.\n";
	}
	
	login('user-id'=>$userid, 'password'=>$password);
	my $xml_file = downloadNeXposeXML();
	logout();
	parseNeXposeXML($xml_file);
	my $tail = substr $csv_buffer, -12;
    if ($tail =~ /Scan Result/)
    {
        $Logger->log($SFHILog::ERROR,"Failed to generate CSV");
        die "Failed to generate CSV\n";
    }
    $Logger->log($SFHILog::DEBUG,"Deleting XML file: $xml_file ..");
    unlink($xml_file) unless defined($keep_xml);

    $Logger->log($SFHILog::INFO,"NeXpose Report Processing Complete");
    #$Logger->log($SFHILog::DEBUG,"Current Memory Utilization :\n". SFHIClient::mem_report());

    return \$csv_buffer;  # return the ref of csv_buffer
}

sub login
{
	my %parms = @_;
	
	my $userid = &escapeXML ($parms{'user-id'});
	my $password = &escapeXML ($parms{'password'});
	
	$Logger->log($SFHILog::DEBUG,"User $userid is logging into $nexposeurl");
	
	my $xml = "<LoginRequest user-id=\'$userid\' password=\'$password\' />";
	my $response = sendXmlRequest($xml);
	if ( $response->is_success() ) {
		my $sessiondata = $xmlresponse->XMLin($response->content());
		$sessionid = $sessiondata->{'session-id'};
		if (!defined $sessionid)
		{
			$Logger->log($SFHILog::ERROR,"Login response: " . $response->content);
	        die("Login failed!\n");
		}
	}
	else {
        $Logger->log($SFHILog::ERROR,"Login response: " . $response->content);
        die("Login failed!\n");
	}
}

sub logout
{
	$Logger->log($SFHILog::INFO,"Logging out of $nexposeurl");
	my $xml = "<LoginRequest />";
	my $response = sendXmlRequest($xml);
	if ( !$response->is_success() ) {
        $Logger->log($SFHILog::ERROR,"Logout response: " . $response->content);
		die("Logout failed!\n");
	}
	
}

sub quit
{
	my ($message, @rest) = @_;
	logout();
	$Logger->log($SFHILog::ERROR,$message);
	die($message);
}

sub downloadNeXposeXML
{
	my $xml = "
	<ReportAdhocGenerateRequest session-id=\'$sessionid\'>
		<AdhocReportConfig format='raw-xml'>
			<Filters>";

	# Create filters for each site and group that is listed
	if ($siteid)
	{
		my @sites = split(/,/, $siteid);
		foreach my $site(@sites)
		{
			$xml .= "<filter type='site' id=\'$site\'/>";
		}
	}
	
	if ($groupid)
	{
		my @groups = split(/,/, $groupid);
		foreach my $group(@groups)
		{
			$xml .= "<filter type='group' id=\'$group\'/>";
		}
	}

	$xml .= "</Filters></AdhocReportConfig></ReportAdhocGenerateRequest>";
	$Logger->log($SFHILog::INFO,"Generating Report");
	my $response = sendXmlRequest($xml);

	# For some reason, response->is_success() returns true even if report isn't successfully generated
	if ( $response->content =~ /ReportAdhocGenerateResponse success="1"/ ) {
		my @content = split("--", $response->content);
		shift(@content);
		shift(@content);
		my @msgparts = $response->parts;
		shift(@msgparts);
		if (!defined $msgparts[0]->content)
		{
			$Logger->log($SFHILog::ERROR,"Report response: " . $response->content);
			quit("Report is empty!\n");
		}
 		my $xmlreport = MIME::Base64::decode_base64($msgparts[0]->content);

		my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time);
	    my $file = $path . '/NeXpose_report' . sprintf("%02d%02d%02d", $hour, $min, $sec) . '.' . 'xml';

	    $Logger->log($SFHILog::DEBUG,"Writing $file ..");
	    open FILE, ">$file" or quit("Unable to open output file for writing: $!");
	    binmode(FILE);
	    print FILE $xmlreport;
	    close FILE;
		
		$Logger->log($SFHILog::INFO,"Report Generation Complete");
	
		return $file;
	}
	else {
        $Logger->log($SFHILog::ERROR,"Report response: " . $response->content);
		quit("Download failed!\n");
	}
}

# Parse the XML And generate the CSV on the fly
sub parseNeXposeXML
{
    my ($xml_file) = @_;

    $Logger->log($SFHILog::INFO,"Processing XML Report");
    $Logger->log($SFHILog::DEBUG,"XML Report : $xml_file");
    $Logger->log($SFHILog::INFO,"Parsing Vulnerability Definitions");
    my $twig = XML::Twig -> new(twig_roots => { 'NexposeReport/VulnerabilityDefinitions' => \&vulndefs_handler });
    $twig->parsefile($xml_file);
    $twig->purge();

    $Logger->log($SFHILog::INFO,"Parsing Nodes");
    $twig = XML::Twig -> new(twig_roots => { 'NexposeReport/nodes/node' => \&nodes_handler });
    $twig->parsefile( $xml_file );
    $twig->purge();
    $csv_buffer .= "ScanFlush\n";
}

# Handler used for processing Vulnerability Definitions
sub vulndefs_handler
{

    my ($twig, $Vuln_Defs) = @_;
	my @vulns;

    if ( (defined $Vuln_Defs) and $Vuln_Defs->has_child('vulnerability') ) {
        @vulns  = $Vuln_Defs->findnodes('vulnerability');
    }
    else {
        $Logger->log($SFHILog::DEBUG,"No vulnerability details are present");
        return 1;
    }

    foreach my $vuln ( @vulns )
    {
		my $text;
        my @references = undef ;
        my @cvevalues;
        my @bugtraqvalues;

        my $vulnid = $vuln->{'att'}->{'id'};
		$vulnid = lc($vulnid);	# Always convert to lowercase to normalize

		my $description = $vuln->first_child('description')->first_child('ContainerBlockElement')->text();
		$description =~ s/"/'/g;	# Convert any double quotes to single quotes so CSV doesn't get messed up
		$description =~ s!\s+! !g;  # Remove extra white spaces
		$description =~ s/[^!-~\s]//g;	# Remove non-ASCII characters
		$vuln_href->{$vulnid}{description} = $description;

        $vuln_href->{$vulnid}{title} = $vuln->{'att'}->{'title'};
        if ($vuln->has_child('references')) {
            @references =  $vuln->first_child('references')->findnodes('reference') ;
            foreach my $ref ( @references) {
				if ($ref->{'att'}->{'source'} eq 'CVE') {
					$text = $ref->text();
					if ( defined $text ) {
	                    next unless ($text =~ /^(?:CVE|CAN)-\d\d\d\d-\d+$/);;
	                    push @cvevalues, $text;
	                }
				}

				if ($ref->{'att'}->{'source'} eq 'BID') {
					$text = $ref->text();
					if ( defined $text ) {
	                    next unless ($text =~ /^\d+$/);
	                    push @bugtraqvalues, $text;
	                }
				}
            }
        }
        $vuln_href->{$vulnid}{cve} = \@cvevalues;
        $vuln_href->{$vulnid}{bugtraq} = \@bugtraqvalues;
    }
    $twig->purge;
}

sub nodes_handler
{
    my ($twig, $host) = @_;
	my $vulns_present = 0;

    return unless defined $host;
    my $addr = $host->{'att'}->{'address'};
    return if( $addr eq '' );
	
	my $host_buffer = undef;
	# Even if a host has multiple hostnames, only take the first one
	if ($hostname_attr)
	{
		if ($host->has_child('names'))
		{
			my $hostname = $host->first_child('names')->first_child('name')->text();
			$host_buffer = 'SetAttributeValue,' . $addr .','. $hostname_attr .','. $hostname ."\n";
			$Logger->log($SFHILog::DEBUG,"   Host attribute ".$hostname_attr. " set to " .$hostname);
		}
	}
	
	# Iterate through OS fingerprints to populate OS or OS attribute fields
	my $os_buffer = undef;
	if ($os_attr)
	{
		my ($vendor_str, $family_str, $devclass_str, $product_str, $version_str) = (undef, undef, undef, undef, undef);
		
		# Go through each OS fingerprint, most confident to least confident. Only populate values if they're empty
		foreach my $os ($host->findnodes('fingerprints/os'))
		{
			$vendor_str = $os->{'att'}->{'vendor'} if !defined $vendor_str;
			$product_str = $os->{'att'}->{'product'} if !defined $product_str;
			$version_str = $os->{'att'}->{'version'} if !defined $version_str;
			$devclass_str = $os->{'att'}->{'device-class'} if !defined $devclass_str;
			$family_str = $os->{'att'}->{'family'} if !defined $family_str;
		}

		if ($os_attr && $vendor_str)
		{
			$os_buffer .= set_os_attr($addr, $vendor_str, $family_str, $devclass_str, $product_str, $version_str);
		}		
	}	
	
    # Vulns must be parsed in 2 places:
		# 1. Inside of tests at root level
		# 2. Inside of tests that are inside of services, which exist inside of endpoints
	# This code is a bit ugly because it's walking through vulns in 2 different parts of tree
	my $vuln_buffer = undef;
	
	foreach my $vuln ($host->findnodes('tests/test'))
	{
		# We only care about vulns that exist in VulnDetails section and have a valid status
		next unless (defined($vuln->{'att'}->{'id'}) && 
					defined($vuln_href->{$vuln->{'att'}->{'id'}}) && 
					(($vuln->{'att'}->{'status'} eq 'vulnerable-exploited') || ($vuln->{'att'}->{'status'} eq 'vulnerable-version')));

		$vuln_buffer .= parsevuln($vuln, $addr);      
	}
	
	foreach my $endpoint ($host->findnodes('endpoints/endpoint'))
	{	
		my $port = $endpoint->{'att'}->{'port'} if defined($endpoint->{'att'}->{'port'});
		my $protocol = $endpoint->{'att'}->{'protocol'} if defined($endpoint->{'att'}->{'protocol'});

		foreach my $service ($endpoint->findnodes('services/service'))
		{
			foreach my $vuln ($service->findnodes('tests/test'))
			{
				next unless (defined($vuln->{'att'}->{'id'}) && 
							defined($vuln_href->{$vuln->{'att'}->{'id'}}) && 
							(($vuln->{'att'}->{'status'} eq 'vulnerable-exploited') || ($vuln->{'att'}->{'status'} eq 'vulnerable-version')));

				$vuln_buffer .= parsevuln($vuln, $addr, $port, $protocol);      
			}
		}
	}

	my $new_host = undef;
    if( $addr ne $last_addr )
    {
        $host_count++;
        $Logger->log($SFHILog::DEBUG,"Start converting on IP $addr ($host_count)...");
		$new_host = 1;
        $last_addr = $addr;
    }

	# We only want to do an AddHost if the host actually has vulns, hostname, or OS data to add
	# NeXpose reports may list hosts with NO valid vulns
	if ($vuln_buffer || $host_buffer || $os_buffer)
	{
        $csv_buffer .= "AddHost,$addr\n" if (($add_host) && ($new_host));
		$csv_buffer .= $host_buffer if ($host_buffer);
		$csv_buffer .= $os_buffer if ($os_buffer);
        $csv_buffer .= $vuln_buffer if ($vuln_buffer);
		$csv_buffer .= "ScanFlush\n" if ($new_host);
	}
    $twig->purge();
}

sub set_os_attr
{
	my ($addr, $vendor_str, $family_str, $devclass_str, $product_str, $version_str) = @_;
	my $os_buffer = undef;
	my $os_str = undef;
	
	$os_str .= "$vendor_str " if defined $vendor_str;
	$os_str .= "$product_str " if defined $product_str;
	$os_str .= "$version_str " if defined $version_str;
	$os_str .= "in $family_str Family " if defined $family_str;
	$os_str .= "in $devclass_str Class" if defined $devclass_str;
	
	$os_buffer = 'SetAttributeValue,' . $addr .','. $os_attr .',';
	$os_buffer .= '"'. SFHIClient::reformat($os_str) .'"' . "\n";
	$Logger->log($SFHILog::DEBUG,"   Host attribute ".$os_attr. " set to " .$os_str);
	
	return $os_buffer;
}

# Populate CSV buffer with information about the vuln
sub parsevuln
{
	my ($vuln, $addr, $port, $protocol) = @_;
	$port = '' if !defined $port;
	$protocol = '' if !defined $protocol;
	
	my $vuln_buffer;
	
	my $vulnid =  $vuln->{'att'}->{'id'};
	$vulnid = lc($vulnid);	# Always convert to lowercase to normalize
	my $vulnidint = convert_vulnid($vulnid);	# Host Input API requires vuln id to be an integer, not a string
	$protocol = '6' if( $protocol eq 'tcp' );
    $protocol = '17' if( $protocol eq 'udp' );
	$port = '' if ($port eq '0');
	$protocol = '' if ($protocol eq 'icmp');

    $Logger->log($SFHILog::DEBUG,"   NeXpose ID: $vulnid");
    $vuln_buffer .= 'AddScanResult,'. $addr .',"NeXpose",'. $vulnidint .',';
    $vuln_buffer .= $port .','. $protocol .',';
	$vuln_buffer .= '"'. SFHIClient::reformat($vuln_href->{$vulnid}{title}) .'",';
	$vuln_buffer .= '"'. SFHIClient::reformat($vuln_href->{$vulnid}{description}) .'",';

    $vuln_buffer .= '"cve_ids: '. join(' ',@{$vuln_href->{$vulnid}{cve}}) .'",';
    $vuln_buffer .= '"bugtraq_ids: '.join(' ',@{$vuln_href->{$vulnid}{bugtraq}}) ."\"\n";
}

# Private functions

sub sendXmlRequest
{
	my $xml = shift;
	my $request = HTTP::Request->new (POST => $nexposeurl);
	$request->content_type ('text/xml');
	$request->content ($xml);
	my $response = $useragent->request($request);
	
	return $response;
}

sub escapeXML()
{
   my ($string) = @_;
   my $line = '';

   #create a character array of the XML data
   my @chars = split (//, $string);

   foreach my $char (@chars)
   {
      my $num = ord($char);
      #this is some kind of funky character
      if (($num < 0x20 && $char ne "\n" && $char ne "\r" && $char ne "\t") || $num > 0x7e) 
      {
         #Restricted characters are not valid even in number character references, so do not keep them.
         if (!isXMLRestricted($num))
         {
            $line .= "&#$num;";
         }
      }
      else
      {
         $line .= $char;
      }
   }
   return $line;
}

sub isXMLRestricted()
{
   my $num = shift;
   return ($num <= 0x8 || $num == 0xb || $num == 0xc || ($num >= 0xe && $num <= 0x1f) ||
         ($num >= 0x7f && $num <= 0x84) || ($num >= 0x86 && $num <= 0x9f));
}

sub convert_vulnid
# Function to convert NeXpose vulnid string into a unique 32-bit integer
{
	my ($vulnid) = @_;
	
	my $md5str = md5_hex($vulnid);
	my $md5strsub = substr $md5str, 0, 8;
	$md5strsub =~ tr/a-f/1-6/;
	return $md5strsub;
}

sub parseNumRanges
# Returns comma-separated list of numbers
# Taken from http://stackoverflow.com/questions/2816816/is-there-a-perl-module-for-parsing-numbers-including-ranges
{
	my ($in) = @_;
	$in =~ s/\s+//g;	# remove spaces
	$in =~ s/(?<=\d)-/../g;	# replace - with ..

	my $range = new Number::Range($in);
	my @array = sort { $a <=> $b } $range->range;

	return join(',', @array);
}

sub vulnListing
{
       my $xml = "<VulnerabilityListingRequest />";
}          
1;

package Rapid7Utils::NeXposeAPI;

use strict;
use LWP::UserAgent;
use Crypt::SSLeay;
use XML::XPath;
use Carp;

sub new
{
   my $class = shift;
   my $self = {};
   bless $self = 
   {
      "host" => "127.0.0.1",
      "port" => "3780",
      "ua" => LWP::UserAgent->new,
      "session-id" => undef,
      "sync-id" => undef,
      @_                            #override the defaults
   }, "Rapid7Utils::NeXposeAPI";
   
   $self->{'ua'}->ssl_opts( verify_hostname => 0 ); # not verifying the hostname is a security risk!
   $self->{'host'} = &escapeXML($self->{'host'});
   $self->{'port'} = &escapeXML($self->{'port'});
   $self->{'session-id'} = &escapeXML($self->{'session-id'});
   $self->{'sync-id'} = &escapeXML($self->{'sync-id'});
   return $self;
}

sub login
{
   my $self = shift;
   my %parameters = @_;

   my $userid = &escapeXML ($parameters{'user-id'});
   my $password = &escapeXML ($parameters{'password'});

   unless ($userid){ croak "ERROR: The 'login' method requires a user-id"; }
   unless ($password){ croak "ERROR: The 'login' method requires a password"; }

   my $xml = "<LoginRequest sync-id=\"$self->{'sync-id'}\" user-id=\"$userid\" password=\"$password\" />";
   print $xml."\n";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue('//LoginResponse/attribute::session-id'))
   {
      $self->{'session-id'} = &escapeXML ($xmlResponse->findvalue ('//LoginResponse/attribute::session-id'));
   }
   
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//LoginResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub logout
{
   my $self = shift;

   my $xml = "<LogoutRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//LogoutResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteListing
{
   my $self = shift;

   my $xml = "<SiteListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteConfig
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = $parameters{'site-id'};
   unless ($siteID){ croak "ERROR: The 'siteConfig' method requires a site-id"; }

   my $xml = "<SiteConfigRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" site-id=\"$siteID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteConfigResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub restart
{
  my $self = shift;
  my %parameters = @_;
  
  my $xml = "<RestartRequest session-id=\"$self->{'session-id'}\" sync-id=\"$self->{'sync-id'}\" />"; 
  my $response = sendXmlRequest ($self, $xml);
  my $xmlResponse = XML::XPath->new (xml => $response->content);
  return $response->content;
}

sub command
{
   my $self = shift;
   my %parameters = @_;
   my $consolecommand = &escapeXML ($parameters{'consolecommand'});
   my $xml = "<ConsoleCommandRequest session-id=\"$self->{'session-id'}\" sync-id=\"$self->{'sync-id'}\">";
   $xml .= "<Command>$consolecommand</Command></ConsoleCommandRequest>";
   print $xml;
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath-> new (xml => $response->content);
   return $response->content;
}

sub update 
{
   my $self = shift;
   my $xml = "<StartUpdateRequest session-id=\"$self->{'session-id'}\" sync-id=\"$self->{'sync-id'}\"/>"; 
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
   return $response->content;
}

sub sendLog
{
   my $self = shift;
   my %parameters = @_;
   my $tourl = &escapeXML ($parameters{'tourl'});
   my $keyid = &escapeXML ($parameters{'keyid'});
   my $transport = &escapeXML ($parameters{'transport'});
   my $fromsender = &escapeXML ($parameters{'fromsender'});
   my $toemail = &escapeXML ($parameters{'toemail'});
   my $relay = &escapeXML ($parameters{'relay'});

   my $xml = "<SendLogRequest session-id=\"$self->{'session-id'}\" sync-id=\"$self->{'sync-id'}\" keyid=\"$keyid\">";
   $xml .= "<Transport protocol=\"$transport\">";
   if ($tourl)
   {
      $xml .= "<URL>$tourl</URL>";
   }
   elsif ($toemail)
   {
      $xml .= "<Email>";
      $xml .= "<Recipient>$toemail</Recipient>";
      $xml .= "<Sender>$fromsender</Sender>";
      $xml .= "<SMTPRelayServer>$relay</SMTPRelayServer>";
      $xml .= "</Email>";
   }
   $xml .= "</Transport>";
   $xml .= "</SendLogRequest>";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
   return $response->content;
}

sub systemInfo
{
   my $self = shift;
   my $xml = "<SystemInformationRequest session-id=\"$self->{'session-id'}\" sync-id=\"$self->{'sync-id'}\"/>";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
   return $response->content;
}

sub siteSave
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = &escapeXML ($parameters{'id'});
   my $siteName = &escapeXML ($parameters{'name'});
   my $riskFactor = '1.0';
   my $siteDescription = &escapeXML ($parameters{'description'});
   my @hosts;
   my @adminCredentials;
   my @alerts;
   my $scanConfig;

   if (exists ($parameters{'riskFactor'}))
   {
      $riskFactor = &escapeXML ($parameters{'riskFactor'});
   }

   unless ($siteID){ croak "ERROR: The 'siteSave' method requires a site 'id'"; }
   unless ($siteName){ croak "ERROR: The 'siteSave' method requires a site 'name'"; }

   my $xml = "<SiteSaveRequest session-id=\"$self->{'session-id'}\" sync-id=\"$self->{'sync-id'}\" >";
   $xml .= "<Site id=\"$siteID\" name=\"$siteName\" riskfactor=\"$riskFactor\" description=\"$siteDescription\">";

   if (exists ($parameters{'Hosts'}))
   {
      @hosts = @{$parameters{'Hosts'}};
   }

   $xml .= "<Hosts>";
   foreach my $host (@hosts)
   {
      foreach my $range (@{$host->{'range'}})
      {
         my $rangeFrom = &escapeXML ($range->{'from'});
         my $rangeTo = &escapeXML ($range->{'to'});

         unless ($rangeFrom){ croak "ERROR: The 'siteSave' Hosts element range is missing the 'from' field"; }

         $xml .= "<range from=\"$rangeFrom\" to=\"$rangeTo\" />";
      }
      foreach my $hostName (@{$host->{'host'}})
      {
         $hostName = &escapeXML ($hostName);
         $xml .= "<host>$hostName</host>";
      }
   }
   $xml .= "</Hosts>";

   if (exists ($parameters{'adminCredentials'}))
   {
      @adminCredentials = @{$parameters{'adminCredentials'}};
   }

   $xml .= "<Credentials>";
   foreach my $creds(@adminCredentials)
   {
      my $service = &escapeXML ($creds->{'service'});
      my $host = &escapeXML ($creds->{'host'});
      my $port = &escapeXML ($creds->{'port'});
      my $user = &escapeXML ($creds->{'userid'});
      my $password = &escapeXML ($creds->{'password'});
      my $realm = &escapeXML ($creds->{'realm'});
      my $data = &escapeXML ($creds->{'data'});

      unless ($service =~ m/^(cvs|ftp|http|as400|notes|tds|sybase|cifs|oracle|mysql|pop|remote execution|snmp|ssh|telnet)$/){ croak "ERROR: The 'siteSave' Credentials element requires a valid 'service'"; }

      $xml .= "<adminCredentials service=\"$service\" host=\"$host\" port=\"$port\" userid=\"$user\" password=\"$password\" realm=\"$realm\">";
      $xml .= "$data</adminCredentials>";
   }
   $xml .= "</Credentials>";

   if (exists ($parameters{'Alerting'}))
   {
      @alerts = @{$parameters{'Alerting'}};
   }

   $xml .= "<Alerting>";
   foreach my $alert(@alerts)
   {
      my $name = &escapeXML ($alert->{'name'});
      my $max = &escapeXML ($alert->{'maxAlerts'});
      my $enabled = $alert->{'enabled'} || 0;
      $enabled = &escapeXML ($enabled);

      unless ($name){ croak "ERROR: The 'siteSave' Alert is missing the alert 'name'"; }
      unless ($max){ croak "ERROR: The 'siteSave' Alert is missing the 'maxAlerts'"; }
      unless ($enabled =~ m/^([0-1]){1}$/){ croak "ERROR: The 'siteSave' Alert 'enabled' bit must be 0 or 1"; }

      $xml .= "<Alert name=\"$name\" enabled=\"$enabled\" maxAlerts=\"$max\">";

      unless ($alert->{'scanFilter'} == 1)
      {
         my $scanStart = $alert->{'scanStart'} || 0;
         my $scanStop = $alert->{'scanStop'} || 0;
         my $scanFailed = $alert->{'scanFailed'} || 0;

         $scanStart = &escapeXML ($scanStart);
         $scanStop = &escapeXML ($scanStop);
         $scanFailed = &escapeXML ($scanFailed);

         unless ($scanStart =~ m/^([0-1]){1}$/)
         { croak "ERROR: The 'siteSave' Alert 'scanStart' bit must be 0 or 1"; }
         unless ($scanStop =~ m/^([0-1]){1}$/)
         { croak "ERROR: The 'siteSave' Alert 'scanStop' bit must be 0 or 1"; }
         unless ($scanFailed =~ m/^([0-1]){1}$/)
         { croak "ERROR: The 'siteSave' Alert 'scanFailed' bit must be 0 or 1"; }

         $xml .= "<scanFilter scanStart=\"$scanStart\" scanStop=\"$scanStop\" scanFailed=\"$scanFailed\" />";
      }

      if ($alert->{'vulnFilter'} == 1)
      {
         my $sevThreshold = &escapeXML ($alert->{'severityThreshold'});
         my $confirmed = $alert->{'confirmed'} || 1;
         my $unconfirmed = $alert->{'unconfirmed'} || 1;

         $confirmed = &escapeXML ($confirmed);
         $unconfirmed = &escapeXML ($unconfirmed);

         unless ($sevThreshold)
         { croak "ERROR: The 'siteSave' method requires the Alert 'Severity Threshold'"; }
         unless ($sevThreshold =~ m/^([0-9]){1}$/ || $sevThreshold =~ m/^(10)$/)
         { croak "ERROR: The 'siteSave' Alert 'Severity Threshold' must be a number from 1-10"; }
         unless ($confirmed =~ m/^([0-1]){1}$/)
         { croak "ERROR: The 'siteSave' Alert 'confirmed' bit must be 0 or 1"; }
         unless ($unconfirmed =~ m/^([0-1]){1}$/)
         { croak "ERROR: The 'siteSave' Alert 'unconfirmed' bit must be 0 or 1"; }

         $xml .= "<vulnFilter severityThreshold=\"$sevThreshold\" confirmed=\"$confirmed\" unconfirmed=\"$unconfirmed\" />";
      }

      if ($alert->{'smtpAlert'} == 1)
      {
         my $sender = &escapeXML ($alert->{'sender'});
         my $server = &escapeXML ($alert->{'server'});
         my $port = $alert->{'port'} || 25;
         my $limit = $alert->{'limitText'} || 0;
         $port = &escapeXML ($port);
         $limit = &escapeXML ($limit);
         my @recipient;

         unless ($limit == 0 || $limit == 1)
         { croak "ERROR: The 'siteSave' Alert 'limitText' bit must be 0 or 1"; }

         if (exists ($alert->{'recipient'}))
         {
            @recipient = @{$alert->{'recipient'}};
         }
         unless (@recipient > 0)
         { croak "ERROR: The 'siteSave' Alert SMTP settings must contain at least one 'recipient'"; }

         $xml .= "<smtpAlert sender=\"$sender\" server=\"$server\" port=\"$port\" limitText=\"$limit\">";

         foreach my $recipient (@recipient)
         {
            $recipient = &escapeXML ($recipient);
            $xml .= "<recipient>$recipient</recipient>";
         }
         $xml .= "</smtpAlert>";
      }
      elsif ($alert->{'snmpAlert'} == 1)
      {
         my $community = &escapeXML ($alert->{'community'});
         my $server = &escapeXML ($alert->{'server'});
         my $port = $alert->{'port'} || 162;
         $port = &escapeXML ($port);

         unless ($community){ croak "ERROR: The 'siteSave' Alert SNMP settings must list a 'community'"; }
         unless ($server){ croak "ERROR: The 'siteSave' Alert SNMP settings must list an SNMP 'server'"; }

         $xml .= "<snmpAlert community=\"$community\" server=\"$server\" port=\"$port\" />";
      }
      elsif ($alert->{'syslogAlert'} == 1)
      {
         my $server = &escapeXML ($alert->{'server'});
         my $port = $alert->{'port'} || 514;
         $port = &escapeXML ($port);

         unless ($server){ croak "ERROR: The 'siteSave' Alert syslog settings must list a syslog 'server'"; }

         $xml .= "<syslogAlert server=\"$server\" port=\"$port\" />";
      }
      else
      {
         croak "ERROR: The 'siteSave' Alert must contain one of the following: smtpAlert, snmpAlert, or syslogAlert";
      }
      $xml .= "</Alert>";
   }
   $xml .= "</Alerting>";

   if (exists ($parameters{'ScanConfig'}))
   {
      $scanConfig = $parameters{'ScanConfig'};
      my $configID = &escapeXML ($scanConfig->{'configID'});
      my $templateID = &escapeXML ($scanConfig->{'templateID'});
      my $engineID = &escapeXML ($scanConfig->{'engineID'});
      my $configVersion = $scanConfig->{'configVersion'} || 3;
      $configVersion = &escapeXML ($configVersion);

      unless ($configID){ croak "ERROR: The 'siteSave' method requires a 'configID'"; }
      unless ($templateID){ croak "ERROR: The 'siteSave' method requires a 'templateID'"; }
      if ($configVersion != 3)
      {
         croak "ERROR: The 'siteSave' Scan Config 'configVersion' can only be set to '3'";
      }
      $xml .= "<ScanConfig configID=\"$configID\" name=\"hack\" templateID=\"$templateID\" engineID=\"$engineID\" configVersion=\"$configVersion\">";

      if ($scanConfig->{'Schedules'} == 1)
      {
         my $schedule = $scanConfig->{'Schedule'};
         my $enabled = $schedule->{'enabled'} || 0;
         $enabled = &escapeXML ($enabled);
         my $type = &escapeXML ($schedule->{'type'});
         my $interval = &escapeXML ($schedule->{'interval'});
         my $start = &escapeXML ($schedule->{'start'});
         my $maxDuration = &escapeXML ($schedule->{'maxDuration'});

         unless ($enabled =~ m/^([0-1]){1}$/)
         { croak "ERROR: The 'siteSave' Scan Config schedule 'enabled' bit must be 0 or 1"; }
         unless ($type){ croak "ERROR: The 'siteSave' Scan Config requires the schedule 'type'"; }
         unless ($type =~ m/^(daily|hourly|monthly-date|monthly-day|weekly)$/)
         { croak "ERROR: The 'siteSave' Scan Config schedule 'type' is not valid"; }
         unless ($interval){ croak "ERROR: The 'siteSave' Scan Config schedule requires a time 'interval'"; }
         unless ($start){ croak "ERROR: The 'siteSave' Scan Config schedule requires a 'start' time"; }

         $xml .= "<Schedules>";
         $xml .= "<Schedule enabled=\"$enabled\" type=\"$type\" interval=\"$interval\" start=\"$start\" maxDuration=\"$maxDuration\" />";
         $xml .= "</Schedules>";
      }

      $xml .= "</ScanConfig>";
   }

   $xml .= "</Site>";
   $xml .= "</SiteSaveRequest>";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteSaveResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteDelete
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = &escapeXML ($parameters{'site-id'});
   unless ($siteID){ croak "ERROR: The 'siteDelete' method requires a site-id"; }

   my $xml = "<SiteDeleteRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" site-id=\"$siteID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteDeleteResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteScan
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = &escapeXML ($parameters{'site-id'});
   unless ($siteID){ croak "ERROR: The 'siteScan' method requires a site-id"; }

   my $xml = "<SiteScanRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" site-id=\"$siteID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteScanResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteScanHistory
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = &escapeXML ($parameters{'site-id'});
   unless ($siteID){ croak "ERROR: The 'siteScanHistory' method requires a site-id"; }

   my $xml = "<SiteScanHistoryRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" site-id=\"$siteID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteScanHistoryResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteDeviceListing
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = &escapeXML ($parameters{'site-id'});

   my $xml = "<SiteDeviceListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" site-id=\"$siteID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteScanHistoryResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub siteDevicesScan
{
   my $self = shift;
   my %parameters = @_;

   my $siteID = &escapeXML ($parameters{'site-id'});
   my @Devices;
   my @Hosts;

   if (exists ($parameters{'Devices'}))
   {
      @Devices = @{$parameters{'Devices'}};
   }

   if (exists ($parameters{'Hosts'}))
   {
      @Hosts = @{$parameters{'Hosts'}};
   }

   unless (@Devices > 0 || @Hosts > 0){ croak "ERROR: The 'siteDevicesScan' method requires at least one device to be specified"; }

   my $xml = "<SiteDevicesScanRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" site-id=\"$siteID\">";

   if (@Devices > 0)
   {
      $xml .= "<Devices>";
      foreach my $device (@Devices)
      {
         my $devID = &escapeXML ($device->{'id'});
         unless ($devID){ croak "ERROR: The 'siteDevicesScan' Devices requires a device 'id'"; }
         $xml .= "<device id=\"$devID\" />";
      }
      $xml .= "</Devices>";
   }

   if (@Hosts > 0)
   {
      $xml .= "<Hosts>";
      foreach my $host (@Hosts)
      {
         foreach my $range (@{$host->{'range'}})
         {
            my $rangeFrom = &escapeXML ($range->{'from'});
            my $rangeTo = &escapeXML ($range->{'to'});

            unless ($rangeFrom){ croak "ERROR: The 'siteDevicesScan' Hosts element range is missing the 'from' field"; }

            $xml .= "<range from=\"$rangeFrom\" to=\"$rangeTo\" />";
         }
         foreach my $hostName (@{$host->{'host'}})
         {
            $hostName = &escapeXML ($hostName);
            $xml .= "<host>$hostName</host>";
         }
      }
      $xml .= "</Hosts>";
   }
   $xml .= "</SiteDevicesScanRequest>";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//SiteScanHistoryResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub deviceDelete
{
   my $self = shift;
   my %parameters = @_;

   my $devID = &escapeXML ($parameters{'device-id'});
   unless ($devID){ croak "ERROR: The 'deviceDelete' method requires a 'device-id'"; }

   my $xml = "<DeviceDeleteRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" device-id=\"$devID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//DeviceDeleteResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub assetGroupListing
{
   my $self = shift;

   my $xml = "<AssetGroupListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//AssetGroupListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub assetGroupConfig
{
   my $self = shift;
   my %parameters = @_;

   my $groupID = &escapeXML ($parameters{'group-id'});
   unless ($groupID){ croak "ERROR: The 'assetGroupConfig' method requires a 'group-id'"; }

   my $xml = "<AssetGroupConfigRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" group-id=\"$groupID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//AssetGroupConfigResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub assetGroupSave
{
   my $self = shift;
   my %parameters = @_;

   my $id = &escapeXML ($parameters{'id'});
   my $name = &escapeXML ($parameters{'name'});
   my $description = &escapeXML ($parameters{'description'});
   my $riskScore = &escapeXML ($parameters{'riskscore'});
   my @Devices;

   if (exists ($parameters{'Devices'}))
   {
      @Devices = @{$parameters{'Devices'}};
   }

   unless ($id){ croak "ERROR: The 'assetGroupSave' method requires an asset group 'id'"; }
   unless ($name){ croak "ERROR: The 'assetGroupSave' method requires a 'name' for the asset group"; }
   unless (@Devices > 0){ croak "ERROR: The 'assetGroupSave' needs at least one device to be specified"; }

   my $xml = "<AssetGroupSaveRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\">";
   $xml .= "<AssetGroup id=\"$id\" name=\"$name\" description=\"$description\" riskscore=\"$riskScore\">";
   $xml .= "<Devices>";
   foreach my $device (@Devices)
   {
      my $devID = &escapeXML ($device->{'id'});
      my $siteID = &escapeXML ($device->{'site-id'});
      my $host = &escapeXML ($device->{'address'});
      my $riskFactor = $device->{'riskfactor'} || '1.0';
      $riskFactor = &escapeXML ($riskFactor);
      my $riskScore = &escapeXML ($device->{'riskscore'});

      unless ($devID){ croak "The 'assetGroupSave' Device list requires an 'id' for each device"; }

      $xml .= "<device id=\"$devID\" site-id=\"$siteID\" address=\"$host\" riskfactor=\"$riskFactor\" riskscore=\"$riskScore\" />";
   }
   $xml .= "</Devices></AssetGroup></AssetGroupSaveRequest>";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//AssetGroupSaveResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub assetGroupDelete
{
   my $self = shift;
   my %parameters = @_;

   my $groupID = &escapeXML ($parameters{'group-id'});
   unless ($groupID){ croak "ERROR: The 'assetGroupDelete' method requires a 'group-id'"; }

   my $xml = "<AssetGroupDeleteRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" group-id=\"$groupID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//AssetGroupDeleteResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub engineListing
{
   my $self = shift;
   my $xml = "<EngineListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//EngineListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub engineActivity
{
   my $self = shift;
   my %parameters = @_;

   my $engineID = &escapeXML ($parameters{'engine-id'});
   unless ($engineID){ croak "ERROR: The 'engineActivity' method requires an 'engine-id'"; }

   my $xml = "<EngineActivityRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" engine-id=\"$engineID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//EngineActivityResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub scanActivity
{
   my $self = shift;
   my $xml = "<ScanActivityRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);
 
   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ScanActivityResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub scanStop
{
   my $self = shift;
   my %parameters = @_;

   my $scanID = &escapeXML ($parameters{'scan-id'});
   unless ($scanID){ croak "ERROR: The 'scanStop' method requires a 'scan-id'"; }

   my $xml = "<ScanStopRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" scan-id=\"$scanID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ScanStopResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub scanStatus
{
   my $self = shift;
   my %parameters = @_;

   my $scanID = &escapeXML ($parameters{'scan-id'});
   unless ($scanID){ croak "ERROR: The 'scanStatus' method requires a 'scan-id'"; }

   my $xml = "<ScanStatusRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" scan-id=\"$scanID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ScanStatusResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub scanStatistics
{
   my $self = shift;
   my %parameters = @_;

   my $scanID = &escapeXML ($parameters{'scan-id'});
   unless ($scanID){ croak "ERROR: This method requires a 'scan-id'"; }

   my $xml = "<ScanStatisticsRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" scan-id=\"$scanID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ScanStatisticsResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub vulnerabilityListing
{
   my $self = shift;
   my $xml = "<VulnerabilityListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//VulnerabilityListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub vulnerabilityDetails
{
   my $self = shift;
   my %parameters = @_;

   my $vulnID = &escapeXML ($parameters{'vuln-id'});
   unless ($vulnID){ croak "ERROR: The 'vulnerabilityDetails' method requires a 'vuln-id'"; }

   my $xml = "<VulnerabilityDetailsRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" vuln-id=\"$vulnID\" />";
   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//VulnerabilityDetailsResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub vulnExceptListing
{
  my $self = shift;
  my %parameters = @_;
  my $status = &escapeXML ($parameters{'status'});
  my $time_duration = &escapeXML ($parameters{'time-duration'});
  my $xml = "<VulnerabilityExceptionListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\"";

  if ($status =~ m/^(Under Review|Approved|Rejected)$/)
  {
     $xml .= " status=\"$self->{'status'}\"";
  }
  if ($time_duration)
  {
     $xml .= " time_duration=\"$self->{'time-duration'}\"";
  }
  $xml .= " />";

  print $xml;

  my $response = sendXmlRequest12 ($self,$xml);
  my $xmlResponse = XML::XPath->new(xml => $response->content);
 
  if ($xmlResponse->findvalue('//XMLResponse/attribute::success') eq '0' ||
      $xmlResponse->findvalue('//VulnerabilityExceptionListingResponse/attribute::success') eq '0'){ croak $response->content; };

  return $response->content;   
}  


sub reportTemplateListing
{
   my $self = shift;
   my $xml = "<ReportTemplateListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportTemplateListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportTemplateConfig
{
   my $self = shift;
   my %parameters = @_;

   my $templateID = &escapeXML ($parameters{'template-id'});
   unless ($templateID){ croak "ERROR: The 'reportTemplateConfig' method requires a 'template-id'"; }

   my $xml = "<ReportTemplateConfigRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" template-id=\"$templateID\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportTemplateListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportTemplateSave
{
   my $self = shift;
   my %parameters = @_;

   my $id = &escapeXML ($parameters{'id'});
   my $name = &escapeXML ($parameters{'name'});
   my $description = &escapeXML ($parameters{'description'});
   my @property;
   my @ReportSection;
   my $showDeviceNames = $parameters{'enabled'} || 0;
   $showDeviceNames = &escapeXML ($showDeviceNames);

   unless ($id){ croak "ERROR: The 'reportTemplateSave' method requires a template 'id'"; }
   unless ($name){ croak "ERROR: The 'reportTemplateSave' method requires a report template 'name'"; }

   my $xml = "<ReportTemplateSaveRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\">";
   $xml .= "<ReportTemplate id=\"$id\" name=\"$name\">";
   $xml .= "<description>$description</description>";

   if (exists ($parameters{'ReportSections'}))
   {
      @ReportSection = @{$parameters{'ReportSections'}};
   }
   unless (@ReportSection){ croak "ERROR: The 'reportTemplateSave' method requires at least one 'ReportSection'"; }

   if (exists ($parameters{'property'}))
   {
      @property = @{$parameters{'property'}};
   }

   $xml .= "<ReportSections>";
   foreach my $prop (@property)
   {
      my $name = &escapeXML ($prop->{'name'});
      my $data = &escapeXML ($prop->{'data'});

      unless ($name){ croak "ERROR: The 'reportTemplateSave' ReportSections property requires a 'name'"; }
      $xml .= "<property name=\"$name\">$data</property>";
   }

   foreach my $ReportSection (@ReportSection)
   {
      my $name = &escapeXML ($ReportSection->{'name'});
      my @properties;

      if ($ReportSection->{'property'})
      {
         @properties = @{$ReportSection->{'property'}};
         $xml .= "<ReportSection name=\"$name\">";
         foreach my $property( @properties )
         {
            my $propertyName = &escapeXML ($property->{'name'});
            my $data = &escapeXML ($property->{'data'});
            unless ($propertyName){ croak "ERROR: The 'reportTemplateSave' ReportSection property requires a 'name'"; }
            $xml .= "<property name=\"$propertyName\"></property>";
         }
         $xml .= "</ReportSection>";
      }
      else
      {
         $xml .= "<ReportSection name=\"$name\" />";
      }
   }
   $xml .= "</ReportSections>";

   unless ($showDeviceNames =~ m/^([0-1]){1}$/)
   { croak "ERROR: The Settings show device names 'enabled' value can only be 0 or 1"; }

   $xml .= "<Settings>";
   $xml .= "<showDeviceNames enabled=\"$showDeviceNames\" />";
   $xml .= "</Settings>";
   $xml .= "</ReportTemplate></ReportTemplateSaveRequest>";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportTemplateSaveResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportListing
{
   my $self = shift;
   my $xml = "<ReportListingRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportListingResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportHistory
{
   my $self = shift;
   my %parameters = @_;

   my $reportCfgID = &escapeXML ($parameters{'reportcfg-id'});
   unless ($reportCfgID){ croak "ERROR: The 'reportHistory' method requires a 'reportcfg-id'"; }

   my $xml = "<ReportHistoryRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" reportcfg-id=\"$reportCfgID\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportHistoryResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportConfig
{
   my $self = shift;
   my %parameters = @_;

   my $reportCfgID = &escapeXML ($parameters{'reportcfg-id'});
   unless ($reportCfgID){ croak "ERROR: The 'reportConfig' method requires a 'reportcfg-id'"; }

   my $xml = "<ReportConfigRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" reportcfg-id=\"$reportCfgID\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportCongigResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportSave
{
   my $self = shift;
   my %parameters = @_;

   my $id = &escapeXML ($parameters{'id'});
   my $name = &escapeXML ($parameters{'name'});
   my $templateID = &escapeXML ($parameters{'template-id'});
   my $format = &escapeXML ($parameters{'format'});
   my $description = &escapeXML ($parameters{'description'});
   my @filters;
   my $compareTo = &escapeXML ($parameters{'compareTo'});
   my $afterScan = $parameters{'after-scan'} || 0;
   $afterScan = &escapeXML ($afterScan);
   my $generateNow = 1;
   
   if (exists ($parameters{'generate-now'}))
   {
      $generateNow = &escapeXML ($parameters{'generate-now'});
   }

   if (exists ($parameters{'Filters'}))
   {
      @filters = @{$parameters{'Filters'}};
   }

   unless (@filters){ croak "ERROR: The 'reportSave' method requires at least one 'filter'"; }
   unless ($id){ croak "ERROR: The 'reportSave' method requires the report 'id'"; }
   unless ($name){ croak "ERROR: The 'reportSave' method requires a report 'name'"; }
   unless ($templateID){ croak "ERROR: The 'reportSave' method requires a report 'template-id'"; }
   unless ($format){ croak "ERROR: The 'reportSave' method requires a file 'format'"; }
   unless ($format =~ m/^(pdf|html|xml|text|csv|raw-xml|rtf)$/)
   { croak "ERROR: The 'reportSave' file 'format', $format is invalid"; }
   unless ($generateNow =~ m/^([0-1]){1}$/)
   { croak "ERROR: The 'reportSave' 'generate-now' bit must be 0 or 1"; }
   unless ($afterScan =~ m/^([0-1]){1}$/)
   { croak "ERROR: The 'reportSave' 'after-scan' bit must be 0 or 1"; }

   my $xml = "<ReportSaveRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" generate-now=\"$generateNow\">";
   $xml .= "<ReportConfig id=\"$id\" name=\"$name\" template-id=\"$templateID\" format=\"$format\">";
   $xml .= "<description>$description</description>";

   $xml .= "<Filters>";
   foreach my $filter (@filters)
   {
      my $type = &escapeXML ($filter->{'type'});
      my $id = &escapeXML ($filter->{'id'});

      unless ($type){ croak "ERROR: The 'reportSave' filter requires a filter 'type'"; }
      unless ($type =~ m/^(site|group|device|scan)$/)
      { croak "ERROR: The 'reportSave' filter 'type' is invalid"; }
      unless ($id){ croak "ERROR: The 'reportSave' filter requires an 'id' of the site, group, device, or scan to filter"; }

      $xml .= "<filter id=\"$id\" type=\"$type\" />";
   }
   $xml .= "</Filters>";

   if ($compareTo)
   {
      $xml .= "<Baseline compareTo=\"$compareTo\" />";
   }

   $xml .= "<Generate after-scan=\"$afterScan\">";
   if (exists ($parameters{'Schedule'}))
   {
      my $schedule = &escapeXML ($parameters{'Schedule'});
      my $enabled = $schedule->{'enabled'} || 0;
      $enabled = &escapeXML ($enabled);
      my $type = &escapeXML ($schedule->{'type'});
      my $interval = &escapeXML ($schedule->{'interval'});
      my $start = &escapeXML ($schedule->{'start'});
      my $notValidAfter = &escapeXML ($schedule->{'notValidAfter'});

      unless ($enabled =~ m/^([0-1]){1}$/)
      { croak "ERROR: The 'reportSave' Generate Schedule 'enabled' bit must be 0 or 1"; }
      unless ($type){ croak "ERROR: The 'reportSave' Generate Schedule 'type' field is required"; }
      unless ($type =~ m/^(daily|hourly|monthly-date|monthly-day|weekly)$/)
      { croak "ERROR: The 'reportSave' Generate Schedule 'type' is not valid"; }
      unless ($interval){ croak "ERROR: The 'reportSave' Generate Schedule requires a time 'interval'"; }
      unless ($start){ croak "ERROR: The 'reportSave' Generate Schedule requires a 'start' time"; }

      $xml .= "<Schedule enabled=\"$enabled\" type=\"$type\" interval=\"$interval\" start=\"$start\" notValidAfter=\"$notValidAfter\" />";
   }
   $xml .= "</Generate>";

   if (exists ($parameters{'Delivery'}))
   {
      my $delivery = $parameters{'Delivery'};
      my $storeOnServer = 1;
      my $location = &escapeXML ($delivery->{'location'});
      my $sendAs = &escapeXML ($delivery->{'sendAs'});
      my $toAll = &escapeXML ($delivery->{'toAllAuthorized'});
      my @Recipients;
      my $smtpServer = &escapeXML ($delivery->{'smtpRelayServer'});
      my $sender = &escapeXML ($delivery->{'Sender'});

      if (exists ($delivery->{'storeOnServer'}))
      {
         $storeOnServer = &escapeXML ($delivery->{'storeOnServer'});
      }

      unless ($storeOnServer =~ m/^([0-1]){1}$/)
      { croak "ERROR: The Storage 'storeOnServer' value can only be 0 or 1"; }
      unless ($sendAs){ croak "ERROR: The 'reportSave' Email 'sendAs' field is required"; }
      unless ($sendAs =~ m/^(file|zip|url)$/)
      { croak "ERROR: The 'reportSave' Email 'sendAs' value specified is not valid"; }

      if (exists ($delivery->{'Recipients'}))
      {
         @Recipients = @{$delivery->{'Recipients'}};
      }

      $xml .= "<Delivery>";
      $xml .= "<Storage storeOnServer=\"$storeOnServer\">";
      $xml .= "<location>$location</location>";
      $xml .= "</Storage>";
      $xml .= "<Email sendAs=\"$sendAs\" toAllAuthorized=\"$toAll\">";
      $xml .= "<Recipients>";
      foreach my $recipient(@Recipients)
      {
         $recipient = &escapeXML ($recipient);
         $xml .= "<Recipient>$recipient</Recipient>";
      }
      $xml .= "</Recipients>";
      $xml .= "<SmtpRelayServer>$smtpServer</SmtpRelayServer>";
      $xml .= "<Sender>$sender</Sender>";
      $xml .= "</Email>";
      $xml .= "</Delivery>";
   }

   if (exists ($parameters{'DBExport'}))
   {
      my $dbexport = $parameters{'DBExport'};
      my $type = &escapeXML ($dbexport->{'type'});
      my $creds = $dbexport->{'credentials'};
      my $userID = &escapeXML ($creds->{'userid'});
      my $password = &escapeXML ($creds->{'password'});
      my $realm = &escapeXML ($creds->{'realm'});
      my $data = &escapeXML ($creds->{'data'});

      unless ($type){ croak "ERROR: The 'reportSave' DBExport 'type' is required"; }      
      $xml .= "<DBExport type=\"$type\">";
      $xml .= "<credentials userid=\"$userID\" password=\"$password\" realm=\"$realm\">";
      $xml .= "$data</credentials>";
      foreach my $param (@{$dbexport->{'param'}})
      {
         my $name = &escapeXML ($param->{'name'});
         my $data = &escapeXML ($param->{'data'});
         unless ($name){ croak "ERROR: The 'reportSave' DBExport param requires a 'name'"; }
         $xml .= "<param name=\"$name\">$data</param>";
      }
      $xml .= "</DBExport>";
   }
   $xml .= "</ReportConfig></ReportSaveRequest>";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportSaveResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportGenerate
{
   my $self = shift;
   my %parameters = @_;

   my $reportID = &escapeXML ($parameters{'report-id'});
   unless ($reportID){ croak "ERROR: The 'reportGenerate' method requires a 'report-id'"; }

   my $xml = "<ReportGenerateRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" report-id=\"$reportID\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportGenerateResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportDelete
{
   my $self = shift;
   my %parameters = @_;

   my $reportCfgID = &escapeXML ($parameters{'reportcfg-id'});
   my $reportID = &escapeXML ($parameters{'report-id'});

   my $xml = "<ReportDeleteRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\" reportcfg-id=\"$reportCfgID\" report-id=\"$reportID\" />";

   my $response = sendXmlRequest ($self, $xml);
   my $xmlResponse = XML::XPath->new (xml => $response->content);

   if ($xmlResponse->findvalue ('//XMLResponse/attribute::success') eq '0' ||
       $xmlResponse->findvalue ('//ReportDeleteResponse/attribute::success') eq '0'){ croak $response->content; };

   return $response->content;
}

sub reportAdhocGenerate
{
   my $self = shift;
   my %parameters = @_;

   my $templateID = &escapeXML ($parameters{'template-id'});
   my $format = &escapeXML ($parameters{'format'});
   my @filters;
   my $compareTo = &escapeXML ($parameters{'compareTo'});

   unless ($templateID){ croak "ERROR: The 'reportAdhocGenerate' method requires a 'template-id'"; }
   unless ($format){ croak "ERROR: The 'reportAdhocGenerate' method requires a file 'format'"; }
   unless ($format =~ m/^(pdf|html|xml|text|csv|raw-xml|rtf)$/)
   { croak "ERROR: The 'reportAdhocGenerate' file 'format', $format is invalid"; }

   if (exists ($parameters{'Filters'}))
   {
      @filters = @{$parameters{'Filters'}};
   }
   unless (@filters){ croak "ERROR: This method requires at least one 'filter'"; }

   my $xml = "<ReportAdhocGenerateRequest sync-id=\"$self->{'sync-id'}\" session-id=\"$self->{'session-id'}\">";
   $xml .= "<AdhocReportConfig template-id=\"$templateID\" format=\"$format\">";
   $xml .= "<Filters>";
   foreach my $filter(@filters)
   {
      my $type = &escapeXML ($filter->{'type'});
      my $id = &escapeXML ($filter->{'id'});

      unless ($type){ croak "ERROR: The 'reportAdhocGenerate' method requires a filter 'type'"; }
      unless ($type =~ m/^(site|group|device|scan)$/)
      { croak "ERROR: The 'reportAdhocGenerate' filter 'type' is invalid"; }
      unless ($id){ croak "ERROR: The 'reportAdhocGenerate' method requires a filter 'id'"; }

      $xml .= "<filter id=\"$id\" type=\"$type\" />";
   }
   $xml .= "</Filters>";

   if ($compareTo)
   {
      $xml .= "<Baseline compareTo=\"$compareTo\" />";
   }
   $xml .= "</AdhocReportConfig></ReportAdhocGenerateRequest>";

   my $response = sendXmlRequest ($self, $xml);

   #The check for success searches for the string 'success="0"' instead of 
   #testing the attribute directly using XML::Simple.
   if ($response->content=~/success="0"/){ croak $response->content; }

   #Adhoc report generation is different compared to the other requests. The
   #output from the sendXMLRequest needs to be returned as is to preserve
   #the data in its base64 format.
   return $response;
}

sub getURI
{
   my $self = shift;
   my %parameters = @_;

   my $uri = $parameters{'uri'};
   my $sessCookie = 'nexposeCCSessionID=' . $self->{'session-id'};
   my $url;
   if ($self->{'port'} == 443)
   {
      $url = 'https://' . $self->{'host'} . $uri;
   }
   else
   {
      $url = 'https://' . $self->{'host'} . ':' . $self->{'port'} . $uri;
   }   
   my $request = HTTP::Request->new (GET => $url);
   $request->header ('Cookie' => $sessCookie);
   my $response = $self->{ua}->request ($request);
   if ($response->code != 200)
   {
      croak "\n\nRequest failed => " . $response->content . "\n\n";
   }
   return $response;
}

sub sendXmlRequest12
{
   my $self = shift;
   my $xml = shift;
   my $uri = '/api/1.2/xml';
   my $url;
   if ($self->{'port'} == 443)
   {
      $url = 'https://' . $self->{'host'} . $uri;
   }
   else
   {
      $url = 'https://' . $self->{'host'} . ':' . $self->{'port'} . $uri;
   }
   my $request = HTTP::Request->new (POST => $url);
   $request->content_type ('text/xml');
   $request->content ($xml);
   my $response = $self->{ua}->request ($request);

   return $response;
}

## Private methods
sub sendXmlRequest
{
   my $self = shift;
   my $xml = shift;
   my $uri = '/api/1.1/xml';
   my $url;
   if ($self->{'port'} == 443)
   {
      $url = 'https://' . $self->{'host'} . $uri;
   }
   else
   {
      $url = 'https://' . $self->{'host'} . ':' . $self->{'port'} . $uri;
   }
   my $request = HTTP::Request->new (POST => $url);
   $request->content_type ('text/xml');
   $request->content ($xml);
   my $response = $self->{ua}->request ($request);

   return $response;
}

sub escapeXML()
{
   my $string = shift;
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


## Accessor methods
sub getSessionID
{
   my $self = shift;
   return $self->{'session-id'};
}

1;


__END__

=head1 NAME

  Rapid7Utils::NeXposeAPI - Provides an API to the NeXpose security console.

=head1 SYNOPSIS

    use lib "C:/cygwin/rapid7/perl-code/";
    use Rapid7Utils::NeXposeAPI;

    my $napi = new Rapid7Utils::NeXposeAPI( "host" => "10.2.33.165" );
    $napi->login( "user-id" => "nxadmin", "password" => "nxadmin" );
    
    if( $napi->getSessionID )
    {
       print $napi->siteDeviceListing;
       print "\n";

       my @siteDevices = ( { "id" => "1" },
                           { "id" => "3" } );

       print $napi->siteDevicesScan( "site-id" => "1", "Devices" => \@siteDevices );
       print "\n";
       print $napi->logout;
    }

The NeXpose API object created is composed of a C<sync-id> which is currently not used, a
C<session-id>, which is set upon successful login, and C<host>.

=head1 DESCRIPTION

This perl module creates an API to the NeXpose security console. 

=head1 INSTALL

=head2 Install Location

If you have access to the PERL installation then create a directory called
'Rapid7Utils' in the 'site/lib/' directory minus the quotes and copy this PERL
module there. Everything should be fine unless any of the used modules are
missing. If you don't have access to the PERL install directories then create
the 'Rapid7Utils' folder where you have access and before you load the
NeXposeAPI module in your PERL script add a line similar to the following
change the path to where ever you created the 'Rapid7Utils' folder:

   use lib "C:/cygwin/rapid7/perl-code/";

=head2 OpenSSL

You must have OpenSSL or SSLeay installed before compiling 
this module.  You can get the latest OpenSSL package from:

  http://www.openssl.org

Also you can get more information by going to the C<Crypt::SSLeay> man page

=head2 Crypt::SSLeay

At the date of writing this documentation ActiveState's Windows version of 
PERL does not have C<Crypt::SSLeay> as part of the repository. To download the 
module start ppm and download the module pre-compiled from the University 
of Winnipeg as such:

    ppm> install http://theoryx5.uwinnipeg.ca/ppms/Crypt-SSLeay.ppd>

For Linux/Unix users checkout CPAN for more information on installation.

=head1 CONSTRUCTOR

=over 4

=item new

Creates a new NeXpose API object.

I<Parameters>:

B<host>

This parameter is optional and can contain an IP address or DNS name. The default 
is '127.0.0.1' a.k.a. 'localhost'.

B<port>

This parameter is optional and should contain an integer from 1 to 65535. The
default is '3780'.


=back

=head1 METHODS

Each method represents a request being sent to the NeXpose API. Each method 
returns the XML content response from the NeXpose API handler regardless of 
success or failure.  The methods use parameter names in the following format:

   method1( "param1" => "val1", "param2" => "val2" )
   method2( "param3" => \@array )

where "val1" and "val2" represent strings or numbers and "\@array" represents
a reference to an array of data. Take care to note that all the non-array 
reference values are double-quoted.

=head2 Session Management

=over 4

=item login

Logs into the NeXpose console with a given user-id and password. 
If an invalid username or password is given login will fail and cause the user
application to fail. Upon successful C<login()> the C<session-id> will be set.

I<Parameters>:

B<user-id>

B<password>

=item logout

Logs the user out of the NeXpose console.

=back

=head2 Site Management

=over 4

=item siteListing

Lists all of the sites the user is authorized to view or manage.

=item siteConfig

Returns the configuration of the site, including its associated devices. 

I<Parameters>:

B<site-id> 

This required parameter contains the database id of the site config to return.

=item siteSave

Save changes to a new or existing site.

I<Parameters>:

B<id>

This required parameter represents the site id of the site to save. A value of
-1 will create a new site.

B<name> 

This required parameter is the name of the site created or changed to.

B<riskFactor>

The current risk factor for the current site. The default is "1.0".

B<description>

The site description. This value is not required nor defaulted if a value is not provided.

B<Hosts>

This parameter contains a PERL array reference of the devices for the given 
site. An example of the data structure in PERL is as follows:

   my @Hosts = ( { 
                   "range" => [ 
                                { "from" => "192.168.0.1", "to" => "192.168.0.253" },
                                { "from" => "127.0.0.1" }
                              ] 
                 },
                 { 
                   "host" => [ 
                               "www.rapid7.com",
                               "server.hostname.com"
                             ] 
                 } 
               );

The C<range> and C<host> elements are optional. The C<from> field is a required
element while the C<to> field is optional. The order of the elements in the array
are not important.

B<adminCredentials>

This parameter contains a PERL array reference of the credentials used in the 
scanning process of a site. An example of how to set this up is as follows:

   my @adminCredentials = ( { 
                              "service" => "Oracle", 
                              "host" => "oracle.server.com",
                              "port" => "442", 
                              "userid" => "o-admin", 
                              "password" => "password",
                              "realm" => "global", 
                              "data" => "Test box" 
                            },
                            { 
                              "service" => "Windows", 
                              "host" => "10.2.33.165",
                              "port" => "80", 
                              "userid" => "charles", 
                              "password" => "password",
                              "realm" => "XP" } );

The C<service> element represents the type of system to connect to. The C<host> 
and C<port> elements are the URL or IP of the site to limit the connection to. 
C<userid> and C<password> are used to attempt a login of the given site. C<realm>
is the domain to connect. C<data> is not used. All of the credential 
parameters are optional.

The C<userid>, C<password> and C<realm> attributes should ONLY be used if a 
security blob cannot be generated and the data is being transmitted/stored 
using external encryption (eg, HTTPS) SiteSaveRequest doesnt handle the 
security blob right now So username/password attributes should be used in 
that case.

B<Alerting>

This parameter contains a PERL array reference of the credentials used in the
scanning process of a site. An example of how to set this up is as follows:

   my @Alerting = ( { "name" => "First Alert",
                      "maxAlerts" => "5",
                      "enabled" => "1",
                      "scanFilter" => "1",
                      "scanStart" => "1",
                      "scanStop" => "1",
                      "scanFailed" => "1",
                      "scanData" => "What's up",
                      "vulnFilter" => "1",
                      "severityThreshold" => "1",
                      "confirmed" => "1",
                      "unconfirmed" => "1",
                      "smtpAlert" => "1",
                      "sender" => "c\@a.com",
                      "server" => "www.rapid7.com",
                      "limitText" => "1",
                      "recipient" => [ "email\@hostname.com", "cagnello\@rapid7.com" ],
                      "snmpAlert" => "0",
                      "community" => "around",
                      "syslogAlert" => "0",
                    } );

The parameter C<name> is required and represents the name of the alert. The 
parameter C<maxAlerts> is required and represents the maximum number of alerts
to send. The enabled bit is optional, defaulting to '0' (disabled) if not 
specified. 

The C<scanFilter> parameter is an optional field that enables the
scan filter options. The C<scanStart>, C<scanStop>, and C<scanFailed> bits 
are optional, default to '0', and represent the scan events to send an alert.

The C<vulnFilter> parameter is optional field that enables the vuln filter 
options. The C<severityThreshold> is a required field with a range from 1-10.
The C<confirmed> and C<unconfirmed> fields are optional.

The C<smtpAlert>, C<snmpAlert>, and C<syslogAlert> parameters are an optional 
enable for determining what protocol to be used to send the alert. The alert 
must contain at least one of the following types of alerts: smtp, snmp, or 
syslog. The C<server> and C<port> parameters apply to the 3 different
protocols.  If the enable for more than one protocol is set only one will be
used, the order is SMTP, SNMP, and Syslog.  The default port for SMTP is 25,
the default port for SNMP is 162, and the default port for syslog is 514.
The C<sender> and C<limitText> fields are optional and specific to SMTP alerts.
The C<recipient> is a required element composed of an array of e-mail 
addresses to send the SMTP alert to. The C<community> field is required and 
is specific to SNMP alerts.

B<ScanConfig>

This parameter contains a PERL hash of the scan configuration used in the 
scanning process of a site. An example of how to set this up is as follows:

   my %ScanConfig = ( "configID" => "1",
                      "templateID" => "full-audit",
                      "engineID" => "-1",
                      "configVersion" => "3",
                      "Schedules" => "1",
                      "Schedule" => { "enabled" => "1", 
                                      "type" => "hourly", 
                                      "interval" => "24", 
                                      "start" => "19981231T00000000",
                                      "maxDuration" => "120",
                                      "notValidAfter" => "20081231T00000000" 
                                    }
                    );

The parameters C<configID> and C<templateID> are required parameters.
The paramter C<engineID> is optional. The C<configVersion> parameter is optional
with a default value of 3 and a valid value of only 3 as well.

The C<Schedules> parameter is an enable bit for the 'Schedule' data.  The 
C<enabled> bit is optional and default to 0. The C<type>, C<interval>, 
C<start> fields are required. The C<maxDuration> and C<notValidAfter> 
fields are optional.

=item siteDelete

Deletes a particular site.

I<Parameters>:

B<site-id>

This parameter is required and represents the C<id> of the site to be deleted.

=item siteScan

Starts a site scan.

I<Parameters>:

B<site-id>

This parameter is required and represents the C<id> of the site to be scanned.

=item siteScanHistory

Lists the information from the previous scans.

I<Parameters>:

B<site-id>

This parameter is required and represents the C<id> of the site to retrieve 
the scan history.

=item siteDeviceListing

Lists all of the devices in a site. If no site-id is specified, then this will
return all of the devices for the NSC grouped by site-id.

I<Parameters>:

B<site-id>

This parameter is optional and represents the C<id> of the site to retrieve the
device listing.

=item siteDevicesScan

Scans a subset of the devices in a given site.

I<Parameters>:

B<site-id>

This parameter is required and represents the C<id> of the site with the 
devices to scan.

B<Devices>

This parameter is required and consists of a PERL array reference of device 
id's to scan. Below is an example of how to create this:

   my @siteDevices = ( 
                       { "id" => "1" },
                       { "id" => "3" }
                     );

B<Hosts>

This parameter contains a PERL array reference of the devices for the given 
site. An example of the data structure in PERL is as follows:

   my @Hosts = ( { 
                   "range" => [ 
                                { "from" => "192.168.0.1", "to" => "192.168.0.253" },
                                { "from" => "127.0.0.1" }
                              ] 
                 },
                 { 
                   "host" => [ 
                               "www.rapid7.com",
                               "server.hostname.com"
                             ] 
                 } 
               );

The C<range> and C<host> elements are optional. The C<from> field is a required
element while the C<to> field is optional. The order of the elements in the array
are not important.

=back

=head2 Device Management

=over 4

=item deviceDetails

Lists the devices information.

I<Parameters>:

B<device-id>

This parameter is required and represents the C<id> of the device to retrieve
the details.

B<summary>

This parameter is a boolean and if set to "1" (true) returns the device summary
without any node information.

=item deviceDelete

Deletes the given device.

I<Parameters>:

This parameter is required and represents the C<id> of the device to delete.

=back

=head2 Asset Group Management

=over 4

=item assetGroupListing

List all of the asset groups the user is authorized to view or manage.

=item assetGroupConfig

Lists the configuration of the asset group including its associated devices.

I<Parameters>:

B<group-id>

This parameter is required and represents the configuration of the asset group
to return.

=item assetGroupSave

Save changes to a new or existing asset group.

I<Parameters>:

B<id>

This parameter is required and represents the asset group to save changes.
To create a new asset group use "-1" for the C<id>.

B<name>

This parameter is required and represents the new name of the asset group
created or the new name to change the asset group.

B<description>

This parameter is optional and represents the asset group description.

B<riskscore>

This parameter is optional. 

B<Devices>

This parameter is required, consisting of a PERL array reference with device
data. The C<id> is required and represents the device id. The C<site-id>,
C<address>, C<riskfactor>, and C<riskscore> are optional parameters. The
C<riskfactor> defaults to '1.0' if not specified. Below is an example of how
to set up this array.

   my @assetGroupDevs = ( { "id" => "3", 
                            "site-id" => "6", 
                            "address" => "workstation", 
                            "riskfactor" => "1.5", 
                            "riskscore" => "2.1" 
                          },
                          { "id" => "14", 
                            "site-id" => "7" 
                          }
                        );

=item assetGroupDelete

Deletes the asset group.

I<Parameters>:

B<group-id>

This parameter is required and represents the asset group to delete.

=back

=head2 Scanning

=over 4

=item engineListing

List all of the Scanning Engines managed by the Web Console.

=item engineActivity

Lists all of the current scan activities for a specific Scanning Engine.

I<Parameters>:

B<engine-id>

This parameter is required and represents the C<id> of the engine to query.

=item scanActivity

Lists all of the current scan activities across all Scanning Engines managed
by the Web Console.

=item scanStop

Stops a running scan.

I<Parameters>;

B<scan-id>

This parameter is required and represents the C<id> of the scan to stop.

=item scanStatus

Checks the current status of a scan.

I<Parameters>;

B<scan-id>

This parameter is required and represents the C<id> of the scan to check.

=item scanStatistics

Gets the scan statistics, including node and vulnerability breakdowns for a
given scan.

I<Parameters>;

B<scan-id>

This parameter is required and represents the C<id> of the scan to check.

=back

=head2 Vulnerability Assessment

=over 4

=item vulnerabilityListing

Lists all of the vulnerabilities checked by NeXpose.

=item vulnerabilityDetails

Lists the full details of a vulnerability including description, cross 
references, and solution

I<Parameters>;

B<vuln-id>

This parameter is required and represents the C<id> of the vulnerabilty.

=back

=head2 Reporting

=over 4

=item reportTemplateListing

Lists all of the report templates the user can access on the Web Console.

=item reportTemplateConfig

Retrieves the configuration for a report template.

I<Parameters>:

B<template-id>

This parameter is required and represents the name of the template 
configuration to retrieve.

=item reportTemplateSave

Saves the configuration for a report template.

I<Parameters>:

B<id>

This parameter is required and represents the C<id> of the report template to 
save. Passing a value of '-1' will create a new report template.

B<name>

This parameter is required and represents the name of the report template
being saved.

B<description>
This parameter is optional and is text description of the template.

B<property>
This parameter is optional and is a characteristic of the template as a whole.

B<ReportSections>

This parameter is required and contains information about the report sections.
Below is an example of how to set up this data array.

   my @ReportSection =( {
                          "name" => "CoverPage",
                          "property" => [ 
                                          { "name" => "Title", "data" => "Stuff" },
                                          { "name" => "Author", "data" => "Charles" } 
                                        ] 
                        },
                        {
                          "name" => "TOC",
                          "property" => [
                                          { "name" => "Footer", "data" => "2008" } 
                                        ] 
                        },
                        { "name" => "RiskAssessment" },
                        { "name" => "SANSTop20DeviceSynopsis" }                     
                      );

B<enabled>

This parameter is optional and defaults to 0 if not given. This lists the 
hostname next to the IP address of the given device.

=item reportListing

List all of the report definitions the user can access on the Web Console.

=item reportHistory

Returns the history of all reports generated with the specified report 
definition.

I<Parameters>:

B<reportcfg-id>

This parameter is required and represents the C<id> of the report.

=item reportConfig

Retrieve the configuration for a report definition.

I<Parameters>:

B<reportcfg-id>

This parameter is required and represents the C<id> of the report.

=item reportSave

Saves the configuration for a report definition.

I<Parameters>:

B<id>

This parameter is required for the Report Config.  A value of '-1' will create
a new Report Config.

B<name>

This parameter is required for the Report Config. This value is required to be
unique.

B<generate-now>

This parameter specifies if a copy of the report should be generated after saving.
Default value is '1'.

B<template-id>

This parameter is required. The value is a string and thus needs to be unique.

B<format>

This parameter is required and represents the type of output file to create. 
Valid formats are pdf, html, xml, text, csv, raw-xml, or rtf.

B<description>

This parameter is optional and describes the Report Config.

B<Filters>

This parameter is required contains a an array of filters.

   my @filters = ( {"id" => "1", "type" => "site"},
                   {"id" => "5233", "type" => "group"},
                   {"id" => "last", "type" => "scan"},
                   {"id" => "agas", "type" => "device"}
                 );

B<id>

This parameter is required for each Filter specified.

B<type>

This parameter is required for the filter. The valid values are site, group,
device, and scan.

B<compareTo>

This parameter is required for the Baseline.

B<after-scan>

This parameter is optional for the report Generation schedule and defaults to 
'1' meaning 'after a scan has completed'.

B<Schedule>

This parameter is optional and is PERL hash. An example of this data structure
is given below:

   my %Schedules = ( "enabled" => "1",
                     "type" => "daily",
                     "interval" => "7",
                     "start" => "20061221T00000000"
                   );

B<enabled>

This parameter is optional for the Schedule and defaults to '1' enabled.

B<type>

This parameter is required and specifies the units for how often the report 
repeats.  Valid values are as follows: daily, hourly, monthly-date, 
monthly-day, weekly.

B<interval>

This parameter is required and is the value used with the 'type' to determine
the numerical repeat interval.

B<start>

This parameter is required and determines when the Schedule is valid.

B<notValidAfter>

This parameter is required and determines then the Schedule is not valid.

B<Delivery>

This parameter is required consisting of a PERL hash map.

   my %Delivery = ( "storeOnServer" => "1",
                    "sendAs" => "zip",
                    "toAllAuthorized" => "1",
                    "Recipients" => \@Recipients,
                    "smtpRelayServer" => "smtp.server.com",
                    "Sender" => "Charles"

B<storeOnServer>

This parameter is optional defaulting to '1'. A value of '1' means the 'store
the report' on the server.

B<location>

This parameter is optional and is the path to the non-default place where the 
report should be stored.

B<sendAs>

This parameter is required and represents how to send the report. Valid values
are as follows: file, zip, url.

B<toAllAuthorized>

This parameter is optional and defaults to '0'.  Setting to '1' will send the
report to all authorized users of the sites, groups, and devices.

B<Recipients>

This parameter is optional and contains an array of e-mail addresses. That can 
be used in the Delivery hash map. An example is listed below.

   my @Recipients = ( "charles\@rapid7.com", "cwa\@rapid7.com" );

B<smtpRelayServer>

This parameter is optional.

B<Sender>

This parameter is optional.

B<DBExport>

This parameter is optional and is a PERL hash of the database export information.

   my %credentials = ( "userid" => "bob",
                       "password" => "password",
                       "realm" => ""
                     );
   my @param = ( { "name" => "", "data" => "" },
                 { "name" => "", "data" => "" },
                 { "name" => "", "data" => "" },
               );
   my %DBExport = ( "type" => "postgres",
                    "credentials" => \%credentials,
                    "param" => \@param
                  );

B<type>

This parameter is required and represents the database type to export to.

B<credentials>

This parameter is optional and is a PERL hash of login information for the 
given database.  The following three parameters are needed for the credentials.

B<userid>

B<password>

B<realm>

B<param>

This parameter is optional and contains an array of additional information 
used for the db credentials.

B<name>

This parameter is required for the 'param' field.

B<data>

This parameter is optional and contains the 'param' information.

=item reportGenerate

Generate a new report using the specified report definition.

I<Parameters>:

B<report-id>

This parameter is required.

=item reportDelete

Deletes a previously generated report or report definition. If both a report id
and a report config id are specified only the report will be deleted. 

I<Parameters>:

B<report-id>

This parameter is optional and represents the report to delete.

B<reportcfg-id>

This parameter is optional and represents the report configuration to delete.

=item sendLog

Sends diagnostics logs to a specified targeted url or email.  Log files are encrypted
by a public PGP key id.  The call will return the status of whether the logs files
were succesfully sent out or not. 

I<Parameters>:

B<transport>

This parameter is required and represents the type of transport to use.  Options to 
choose from are "smtp", "http", and "https".

B<tourl>

This parameter is required if "http" or "https" is choosen.  This parameter represents
the url to send the log files to.

B<keyid>

This parameter is required and represents an PGP Key ID in Hexadecimal format.

B<fromsender>

This parameter is required if "smtp" is choosen.  This parameter represents the sender's
email address.

B<toemail>

This parameter is required if "smtp" is choosen.  This parameter represents the recipient's
email address.

B<relay>

This parameter is optional and represents the relay server location.

=item update

Issues an update request and returns the status of whether the update request was recieved
or not. 

=item systemInfo

Obtains system information of the NSC.

=item restart

Issues a restart request to the NSC where restart should happen immediately.

=item command 

Issues a console command to the NSC returning the command issued and the output of the command.

I<Parameters>:

B<consolecommand>

This parameter is required and represents the console command to be issued. 

=item reportAdhocGenerate

Creates a report and returns the data without storing the report config.  
The output is MIME data in base64 format.

I<Parameters>:

B<template-id>

This parameter is required and represents the report template to use.

B<format>

This parameter is required and represents the file format. Valid formats are
pdf, html, xml, text, csv, raw-xml, or rtf.

B<Filters>

This parameter is required and can only be one of these: site, group, device, 
or scan.

B<compareTo>

This parameter is required and represents the date to use as the baseline scan
in ISO 8601 format. Additionally, 'first' can be used for the first run scan, 
or 'previous' for the most recently run scan prior to the current scan.

=item getURI

A utility function to perform a get request. This function can be used to
get raw reports from the given URI in the report history.

I<Parameters>:

B<uri>

This parameter is required.

=back

=head1 BUGS

Please report them.

=head1 SEE ALSO

L<LWP::UserAgent>,
L<HTTP::Response>,
L<Crypt::SSLeay>,
L<XML::XPath>,
L<Carp::Carp>

=cut

/*

Vulnerability Exceptions

vulnExceptListing
  status
  time-duration
vulnExceptCreate
  vuln-id
  exception-id
  submitter
  reviewer
  status
  reason
  scope
  device-id
  port-no
  expiration-date
  vuln-key
vulnExceptResubmit
  exception-id
  reason
  comment
vulnExceptRecall
  exception-id
vulnExceptApprove
  exception-id
  comment
vulnExceptReject
  exception-id
vulnExceptDelete
  exception-id
vulnExceptUpdateComment
vulnExceptUpdateExpiry
*/

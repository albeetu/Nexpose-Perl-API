#!/usr/bin/perl
 
use strict;
use lib "/home/atu/Nexpose-Perl-API/lib";
use Rapid7Utils::NeXposeAPI;
use Data::Dumper;
use feature 'say';

my $napi = new Rapid7Utils::NeXposeAPI ("host" => "localhost");
say Dumper( $napi);
print STDERR $napi->login ("user-id" => "v4test", "password" => "buynexpose");
print STDERR "Connecting to: $napi->{'host'}\n\n";

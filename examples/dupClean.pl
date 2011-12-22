#!/usr/bin/perl
use strict;
use Rapid7Utils::NeXposeAPI;
my $napi = new Rapid7Utils::NeXposeAPI ("host" => "localhost");
print STDERR $napi->login ("user-id" => "v4test", "password" => "buynexpose");
print STDERR "Connecting to: $napi->{'host'}\n\n";

#!/usr/bin/perl

=head1 NAME

client.pl - 

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut


use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin.'/lib';

use Net::TacacsPlus::Constants;
use Net::TacacsPlus qw{ tacacs_client };

exit main();

sub main {
	
	my $username = 'user';
	my $password = '123';
	
	my $client = tacacs_client(
		'host' => 'localhost',
		'port' => '4949',
		'key'  => 'secret',
	);
	
	if ($client->authenticate($username, $password, TAC_PLUS_AUTHEN_TYPE_PAP)){                   
		print "Authentication successful.\n";                                  
	} else {                                                    
		print "Authentication failed: ".$client->errmsg()."\n";         
	}                                                           
	
	return 0;
}





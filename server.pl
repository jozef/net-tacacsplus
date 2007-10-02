#!/usr/bin/perl

=head1 NAME

server.pl - example Tacacs+ server

=head1 SYNOPSIS

	./server.pl

=head1 DESCRIPTION

=cut


use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin.'/lib';

use Log::Log4perl qw(:nowarn :easy :no_extra_logdie_message);
Log::Log4perl::init($FindBin::Bin.'/log4perl.conf');

use POE::Component::Server::TacacsPlus;
use Net::TacacsPlus::Constants;

my %password_of = (
	'user' => '123', 
);

exit main();

sub main {
	POE::Component::Server::TacacsPlus->spawn(
		'server_port' => 4949,
		'key'         => 'secret',
		'handler_for' => {
			TAC_PLUS_AUTHEN() => {
				TAC_PLUS_AUTHEN_TYPE_PAP() => \&check_pap_authentication,
			},
		},
	);
	
	POE::Kernel->run();
	
	return 0;
}

sub check_pap_authentication {
	my $username = shift;
	my $password = shift;
	
	if (($password_of{$username} eq $password)) {
		INFO 'successfull auth of '.$username;
		return 1;
	}

	WARN 'failed auth of '.$username;
	return 0;
}

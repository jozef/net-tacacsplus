#!/usr/bin/perl

=head1 NAME

xxx - desc

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut


use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin.'/lib';

use Log::Log4perl qw(:nowarn :easy :no_extra_logdie_message);
Log::Log4perl::init($FindBin::Bin.'/log4perl.conf');

use POE::Component::Server::TacacsPlus;

exit main();

sub main {
	POE::Component::Server::TacacsPlus->spawn(
		'server_port' => 4949,
		'key'         => 'secret',
	);
	
	POE::Kernel->run();
	
	return 0;
}

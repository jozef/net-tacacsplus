#!/usr/bin/perl

use strict;
use warnings;

use Test::More;# 'no_plan';
BEGIN { plan tests => 5 };

use English;

BEGIN {
	use_ok ( 'Net::TacacsPlus 1.03', qw{ tacacs_client }) or exit;
	use_ok ( 'Net::TacacsPlus::Constants' ) or exit;
}

my $client = tacacs_client(
	'host' => 'localhost',
	'key'  => 'test',
);

isa_ok($client, 'Net::TacacsPlus::Client');

#online test to create ::Client object and connect to tacacs server
SKIP: {

	skip "skipping online tests. set TACACS_SERVER, TACACS_SECRET, TACACS_USER and TACACS_PAP_PASSWORD environmental variables to activate them.", 1
		if (!$ENV{'TACACS_SERVER'}
			or !$ENV{'TACACS_SECRET'}
			or !$ENV{'TACACS_USER'}
			or !$ENV{'TACACS_PAP_PASSWORD'}
		);

	my $tacacs_server = $ENV{'TACACS_SERVER'};
	my $tacacs_secret = $ENV{'TACACS_SECRET'};

	my $client = tacacs_client(
		'host' => $tacacs_server,
		'key'  => $tacacs_secret,
	);
	
	isa_ok($client, 'Net::TacacsPlus::Client');
	ok($client->authenticate(
			$ENV{'TACACS_USER'},
			$ENV{'TACACS_PAP_PASSWORD'},
			TAC_PLUS_AUTHEN_TYPE_PAP
		),
		'try to do PAP auth '.$EVAL_ERROR
	);
}

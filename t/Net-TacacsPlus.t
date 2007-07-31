
use Test::More;# 'no_plan';
BEGIN { plan tests => 2 };

BEGIN {
	use_ok ( 'Net::TacacsPlus', qw{ tacacs_client }) or exit;
}

#online test to create ::Client object and connect to tacacs server
SKIP: {

	skip "skipping online tests. set TACACS_SERVER and TACACS_SECRET environmental variables to activate them.", 1
		if ((not exists $ENV{'TACACS_SERVER'}) or (not exists $ENV{'TACACS_SECRET'}));

	my $tacacs_server = $ENV{'TACACS_SERVER'};
	my $tacacs_secret = $ENV{'TACACS_SECRET'};

	my $client = tacacs_client(
		'host' => $tacacs_server,
		'key'  => $tacacs_secret,
	);
	
	isa_ok($client, 'Net::TacacsPlus::Client')
		or diag 'if it fails try your self - "telnet '.$tacacs_server.' 49"';

}

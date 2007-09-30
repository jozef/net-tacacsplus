package POE::Component::Server::TacacsPlus;

use strict;
use warnings;

use Socket qw(inet_ntoa);
use POE qw{
	Wheel::SocketFactory
	Wheel::ReadWrite
	Filter::TacacsPlus
	Driver::SysRW
};
use Log::Log4perl qw(:nowarn :easy :no_extra_logdie_message);

our $SERVER_PORT = 49;

sub spawn {
	my $class = shift;
	my @heap  = @_; 
	
	POE::Session->create(
		inline_states => {
			_start            => \&server_start,
			accept_new_client => \&accept_new_client,
			accept_failed     => \&accept_failed,
			_stop             => \&server_stop,
		},
		heap => {
			@heap,
		},
	);

}

sub server_start {
	my $heap     = $_[HEAP];
	
	$SERVER_PORT = $heap->{'server_port'} if exists $heap->{'server_port'};
	
	$heap->{'listener'} = new POE::Wheel::SocketFactory(
  		BindPort     => $SERVER_PORT,
		Reuse        => 'yes',
		SuccessEvent => 'accept_new_client',
		FailureEvent => 'accept_failed',
	);
	INFO 'SERVER: Started listening on port ', $SERVER_PORT;
}

sub server_stop {
	INFO "SERVER: Stopped.\n";
}

sub accept_new_client {
	my $heap      = $_[HEAP];
	my $socket    = $_[ARG0];
	my $peer_addr = $_[ARG1];
	my $peer_port = $_[ARG2];
	
	$peer_addr = inet_ntoa($peer_addr);

	POE::Session->create(
		inline_states => {
			_start      => \&child_start,
			_stop       => \&child_stop,
			child_input => \&child_input,
			child_done  => \&child_done,
			child_error => \&child_error,
		},
		args => [ $socket, $peer_addr, $peer_port ],
		heap => {
			'key' => $heap->{'key'}
		},
	);
	DEBUG 'SERVER: Got connection from '.$peer_addr.':'.$peer_port;
}


sub accept_failed {
	my $function = $_[ARG0];
	my $error    = $_[ARG2];
	my $heap     = $_[HEAP];

	delete $heap->{'listener'};
	ERROR 'SERVER: call to '.$function.'() failed: $error.';
}


sub child_start {
	my $heap      = $_[HEAP];
	my $socket    = $_[ARG0];
	my $peer_addr = $_[ARG1];
	my $peer_port = $_[ARG2];

	$heap->{'peername'} = $peer_addr.':'.$peer_port;

	$heap->{'readwrite'} = new POE::Wheel::ReadWrite (
		Handle => $socket,
		Driver => new POE::Driver::SysRW(),
		Filter => new POE::Filter::TacacsPlus(
			'key' => $heap->{'key'}
		),
		InputEvent   => 'child_input',
		ErrorEvent   => 'child_error',
	);

	DEBUG 'CHILD: Connected to '.$heap->{'peername'};
}


sub child_stop {
	DEBUG "CHILD: Stopped.\n";
}


sub child_input {
	my $data = $_[ARG0];
	my $heap = $_[HEAP];

	use Data::Dumper;
	DEBUG "CHILD: Got input from peer: ".Dumper($data);
	
	LOGDIE "debug> ".$data->type;

#	$heap->{'readwrite'}->put( $@ || $result );
}


sub child_done {
	my $heap = $_[HEAP];

	delete $heap->{'readwrite'};
	DEBUG "CHILD: disconnected from ", $heap->{'peername'};
}


sub child_error {
	my $function = $_[ARG0];
	my $error    = $_[ARG2];
	my $heap     = $_[HEAP];

	delete $heap->{'readwrite'};
	ERROR 'CHILD: call to '.$function.'() failed: '.$error if $error;
}

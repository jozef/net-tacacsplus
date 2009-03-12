=head1 NAME

Net::TacacsPlus::Client - Tacacs+ client library

=head1 SYNOPSIS

	use Net::TacacsPlus::Client;
	use Net::TacacsPlus::Constants;
	
	my $tac = new Net::TacacsPlus::Client(
				host => 'localhost',
				key => 'secret');
	
	if ($tac->authenticate($username, $password, TAC_PLUS_AUTHEN_TYPE_PAP)){                   
		print "Authentication successful.\n";                                  
	} else {                                                    
		print "Authentication failed: ".$tac->errmsg()."\n";         
	}                                                           

	my @args = ( 'service=shell', 'cmd=ping', 'cmd-arg=10.0.0.1' );
	my @args_response;
	if($tac->authorize($username, \@args, \@args_response))
	{
		print "Authorization successful.\n";
		print "Arguments received from server:\n";
		print join("\n", @args_response);
	} else {
		print "Authorization failed: " . $tac->errmsg() . "\n";
	}

	@args = ( 'service=shell', 'cmd=ping', 'cmd-arg=10.0.0.1' );
	if($tac->account($username, \@args))
	{
		print "Accounting successful.\n";
	} else {
		print "Accounting failed: " . $tac->errmsg() . "\n";
	}

=head1 DESCRIPTION

Currently only PAP and ASCII authentication can be used agains Tacacs+ server.

Tested agains Cisco ACS 3.3 and Cisco (ftp://ftp-eng.cisco.com/pub/tacacs/) tac-plus server.

=cut


package Net::TacacsPlus::Client;

our $VERSION = '1.06';

use strict;
use warnings;

use Carp::Clan;
use IO::Socket;
use Exporter;
use 5.006;
use Fcntl qw(:DEFAULT);
use English qw( -no_match_vars );

use Net::TacacsPlus::Constants 1.03;
use Net::TacacsPlus::Packet 1.03;

use base qw{ Class::Accessor::Fast };

__PACKAGE__->mk_accessors(qw{
	timeout
	port
	host
	key
	
	tacacsserver
	session_id
	seq_no
	errmsg
	authen_method
	authen_type
});

our @EXPORT_OK = ('authenticate', 'authorize', 'account');

my $DEFAULT_TIMEOUT = 15;
my $DEFAULT_PORT    = 49;

=head1 METHODS

=over 4

=item new( somekey => somevalue )

required parameters: host, key

	host	- tacacs server
	key	- ecryption secret

optional parameters: timeout, port

	timeout	- tcp timeout
	port	- tcp port

=cut

sub new {
	my $class = shift;
	my %params = @_;

	#let the class accessor contruct the object
	my $self = $class->SUPER::new(\%params);
	
	$self->timeout($DEFAULT_TIMEOUT) if not defined $self->timeout;
	$self->port($DEFAULT_PORT)       if not defined $self->port;

	return $self;
}

=item close()

Close socket connection.

=cut

sub close {
	my $self = shift;

	if ($self->tacacsserver) {
		if (!close($self->tacacsserver)) { warn "Error closing IO socket!\n" };
		$self->tacacsserver(undef);
	}
}

=item init_tacacs_session()

Inititalize socket connection to tacacs server.

=cut

sub init_tacacs_session
{
	my $self = shift;

	my $remote;
	$remote = IO::Socket::INET->new(Proto => "tcp", PeerAddr => $self->host,
					PeerPort => $self->port, Timeout => $self->timeout);
	croak("unable to connect to " . $self->host . ":" . $self->port . "\n")
		if not defined $remote;
	
	$self->tacacsserver($remote);
	$self->session_id(int(rand(2 ** 32 - 1)));	#2 ** 32 - 1
	$self->seq_no(1);
	$self->errmsg('');
}

=item errmsg()

Returns latest error message

=item authenticate(username, password, authen_type)

username		- tacacs+ username
password		- tacacs+ user password
authen_type		- TAC_PLUS_AUTHEN_TYPE_ASCII | TAC_PLUS_AUTHEN_TYPE_PAP

=cut

sub authenticate {
	my ($self,$username,$password,$authen_type) = @_;

	#init session. will die if unable to connect.
	$self->init_tacacs_session();

	my $status;
	eval {
		#tacacs+ START packet
		my $pkt;

		if ($authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII)
		{
			$pkt = Net::TacacsPlus::Packet->new(
				#header
				'type' => TAC_PLUS_AUTHEN,
				'seq_no' => $self->seq_no,
				'flags' => 0,
				'session_id' => $self->session_id,
				'authen_type' => $authen_type,
				#start
				'action' => TAC_PLUS_AUTHEN_LOGIN,
				'user' => $username,
				'key' => $self->key,
				'rem_addr' => inet_ntoa($self->tacacsserver->sockaddr)
				);
		} elsif ($authen_type == TAC_PLUS_AUTHEN_TYPE_PAP)
		{
			$pkt = Net::TacacsPlus::Packet->new(
				#header
				'type' => TAC_PLUS_AUTHEN,
				'seq_no' => $self->seq_no,
				'flags' => 0,
				'session_id' => $self->session_id,
				'authen_type' => $authen_type,
				'minor_version' => 1,
				#start
				'action' => TAC_PLUS_AUTHEN_LOGIN,
				'key' => $self->key,
				'user' => $username,
				'data' => $password,
				'rem_addr' => inet_ntoa($self->tacacsserver->sockaddr)
				);
		} else {
			croak ('unsupported "authen_type" '.$authen_type.'.');
		}

		$pkt->send($self->tacacsserver);

		#loop through REPLY/CONTINUE packets
		do {
			#receive reply packet
			my $raw_reply;
			$self->tacacsserver->recv($raw_reply,1024);
			croak ("reply read error ($raw_reply).") if not length($raw_reply);

			my $reply = Net::TacacsPlus::Packet->new(
						'type' => TAC_PLUS_AUTHEN,
						'raw' => $raw_reply,
						'key' => $self->key,
						);

			Net::TacacsPlus::Packet->check_reply($pkt,$reply);
			$self->seq_no($reply->seq_no()+1);

			$status=$reply->status();
			if ($status == TAC_PLUS_AUTHEN_STATUS_GETUSER)
			{
				$pkt = Net::TacacsPlus::Packet->new(
					#header
					'type' => TAC_PLUS_AUTHEN,
					'seq_no' => $self->seq_no,
					'session_id' => $self->session_id,
					#continue
					'user_msg' => $username,
					'data' => '',
					'key' => $self->key,
					);
				$pkt->send($self->tacacsserver);
			} elsif ($status == TAC_PLUS_AUTHEN_STATUS_GETPASS)
			{
				$pkt = Net::TacacsPlus::Packet->new(
					#header
					'type' => TAC_PLUS_AUTHEN,
					'seq_no' => $self->seq_no,
					'session_id' => $self->session_id,
					#continue
					'user_msg' => $password,
					'data' => '',
					'key' => $self->key,
					);
				$pkt->send($self->tacacsserver);
			} elsif ($status == TAC_PLUS_AUTHEN_STATUS_ERROR)
			{
				croak('authen status - error');
			} elsif (($status == TAC_PLUS_AUTHEN_STATUS_FAIL) || ($status == TAC_PLUS_AUTHEN_STATUS_PASS))
			{
			} else
			{
				die('unhandled status '.(0 + $status).' (wrong secret key?)'."\n");
			}
		} while (($status != TAC_PLUS_AUTHEN_STATUS_FAIL) && ($status != TAC_PLUS_AUTHEN_STATUS_PASS))
	};
	if ($EVAL_ERROR)
	{
		$self->errmsg($EVAL_ERROR);
		$self->close();
		return undef;
	}
	
	$self->close();
	return undef if $status == TAC_PLUS_AUTHEN_STATUS_FAIL;

	$self->authen_method(TAC_PLUS_AUTHEN_METH_TACACSPLUS); # used later for authorization
	$self->authen_type($authen_type); # used later for authorization
	return 1;
}

=item authorize(username, args, args_response)

username		- tacacs+ username
args			- tacacs+ authorization arguments
args_response   - updated by tacacs+ authorization arguments returned by server (optional)

=cut

sub authorize
{
	my ($self, $username, $args, $args_response) = @_;
	
	$args_response = [] if not defined $args_response;		
	croak 'pass array ref as args_response parameter' if ref $args_response ne 'ARRAY'; 

	my $status;	
	eval {
		check_args($args);
		$self->init_tacacs_session();

		# tacacs+ authorization REQUEST packet
		my $pkt = Net::TacacsPlus::Packet->new(
			#header
			'type' => TAC_PLUS_AUTHOR,
			'seq_no' => $self->seq_no,
			'flags' => 0,
			'session_id' => $self->session_id,
			#request
			'authen_method' => $self->authen_method,
			'authen_type' => $self->authen_type,
			'user' => $username,
			'args' => $args,
			'key' => $self->key,
			);
		
		$pkt->send($self->tacacsserver);
		
		#receive reply packet
		my $raw_reply;
		$self->tacacsserver->recv($raw_reply,1024);
		croak("reply read error ($raw_reply).") if not length($raw_reply);

		my $reply = Net::TacacsPlus::Packet->new(
					'type' => TAC_PLUS_AUTHOR,
					'raw' => $raw_reply,
					'key' => $self->key,
					);

		Net::TacacsPlus::Packet->check_reply($pkt,$reply);
		$self->seq_no($reply->seq_no()+1);

		$status = $reply->status();
		if ($status == TAC_PLUS_AUTHOR_STATUS_ERROR)
		{
			croak('author status - error'); 
		} elsif ($status == TAC_PLUS_AUTHOR_STATUS_PASS_ADD ||
			$status == TAC_PLUS_AUTHOR_STATUS_PASS_REPL)
		{
			@{$args_response} = @{$reply->args()}; # make any arguments from server available to caller
		} elsif ($status == TAC_PLUS_AUTHOR_STATUS_FAIL)
		{
		} else
		{
			croak('unhandled status '.(0 + $status).'');
		}
	};
	if ($EVAL_ERROR)
	{
		$self->errmsg($EVAL_ERROR);
		$self->close();
		return undef;
	}

	$self->close();
	return undef if $status == TAC_PLUS_AUTHOR_STATUS_FAIL;
	return $status;
}

=item check_args([])

Check if the arguments comply with RFC.

=cut

sub check_args
{
	my $args = shift;
	my @args = @{$args};
	my %args;
	foreach my $arg (@args)
	{
		if ($arg =~ /^([^=*]+)[=*](.*)$/)
		{
			$args{$1} = $2;
		} else
		{
			croak("Invalid authorization argument syntax: $arg");
		}
	}
	croak("Missing mandatory argument 'service'")
		if (!$args{'service'});
	croak("Must supply 'cmd' argument if service=shell is specified")
		if($args{'service'} eq 'shell' and !exists($args{'cmd'}));
	# TODO: more RFC checks
}
	

=item account(username, args)

username		- tacacs+ username
args			- tacacs+ authorization arguments
flags			- optional: tacacs+ accounting flags
			  default: TAC_PLUS_ACCT_FLAG_STOP
=cut

sub account 
{
	my ($self,$username,$args,$flags) = @_;
	
	my $status;
	eval {
		$self->init_tacacs_session();

		# tacacs+ accounting REQUEST packet
		my $pkt = Net::TacacsPlus::Packet->new(
			#header
			'type' => TAC_PLUS_ACCT,
			'seq_no' => $self->seq_no,
			'flags' => 0,
			'session_id' => $self->session_id,
			#request
			'acct_flags' => $flags,
			'authen_method' => $self->authen_method,
			'authen_type' => $self->authen_type,
			'user' => $username,
			'args' => $args,
			'key' => $self->key,
			);
		
		$pkt->send($self->tacacsserver);
		
		#receive reply packet
		my $raw_reply;
		$self->tacacsserver->recv($raw_reply,1024);
		croak("reply read error ($raw_reply).") if not length($raw_reply);

		my $reply = Net::TacacsPlus::Packet->new(
					'type' => TAC_PLUS_ACCT,
					'raw' => $raw_reply,
					'key' => $self->key,
					);

		Net::TacacsPlus::Packet->check_reply($pkt,$reply);
		$self->seq_no($reply->seq_no()+1);

		$status = $reply->status();
		if ($status == TAC_PLUS_ACCT_STATUS_ERROR)
		{
			croak('account status - error'); 
		} elsif ($status == TAC_PLUS_ACCT_STATUS_SUCCESS)
		{
		} else
		{
			croak('unhandled status '.(0 + $status).'');
		}
	};
	if ($EVAL_ERROR)
	{
		$self->errmsg($EVAL_ERROR);
		$self->close();
		return undef;
	}

	$self->close();
	return undef if $status == TAC_PLUS_ACCT_STATUS_ERROR;
	return $status;
}

sub DESTROY {
	my $self = shift;

	$self->close();
}

1;

=back

=head1 AUTHOR

Jozef Kutej - E<lt>jkutej@cpan.orgE<gt>

Authorization and Accounting contributed by Rubio Vaughan E<lt>rubio@passim.netE<gt>

=head1 VERSION

1.06

=head1 SEE ALSO

tac-rfc.1.78.txt, Net::TacacsPlus::Packet

Complete client script C<Net-TacacsPlus/examples/client.pl>.

=head1 TODO

	tacacs+ CHAP, ARAP, MSCHAP authentication

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Jozef Kutej

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut

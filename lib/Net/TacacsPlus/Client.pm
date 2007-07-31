=head1 NAME

Net::TacacsPlus::Client - Tacacs+ client library

=head1 SYNOPSIS

	use Net::TacacsPlus::Client;
	use Net::TacacsPlus::Constants;
	
	my $tac = new Net::TacacsPlus::Client(
				host => 'localhost',
				key => 'secret');
	
	if ($tac->authenticate($username, $password, TAC_PLUS_AUTHEN_TYPE_PAP)){                   
		print "Granted\n";                                  
	} else {                                                    
		print "Denied: ".$tac->{'errmsg'}."\n";         
	}                                                           

=head1 DESCRIPTION

Currently only PAP and ASCII authentication can be used agains Tacacs+ server.

=head1 AUTHOR

Jozef Kutej - E<lt>jozef@kutej.netE<gt>

=head1 BUGS

not known

=head1 SEE ALSO

tac-rfc.1.76.txt, Net::TacacsPlus::Packet

=head1 TODO

	tacacs+ CHAP, ARAP, MSCHAP authentication
	tacacs+ authorization
	tacacs+ accounting

=cut


package Net::TacacsPlus::Client;

our $VERSION = '1.02';

use Carp::Clan;
use IO::Socket;
use Exporter;
use 5.006;

@ISA = ('Exporter');
@EXPORT_OK = ('authenticate');

use Net::TacacsPlus::Constants;
use Net::TacacsPlus::Packet;

my $errmsg="";

#seed rand for session id generation
srand (time ^ $$ ^ unpack "%L*", `ps axww | gzip`);

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
	my $self = {};
	
	bless $self, $class;
	
	$self->{'timeout'} = $params{'timeout'} ? $params{'timeout'} : 15;
	$self->{'port'} = $params{'port'} ? $params{'port'} : 'tacacs';
	$self->{'host'} = $params{'host'};
	$self->{'key'} = $params{'key'};
	$self->{'seq_no'} = 1;
	$self->{'errmsg'} = "";
	
	eval {
		$self->init_tacacs_session();
	};
	if ($@)
	{
		#error initializing session
		undef $self;
	}

	return $self;			
}

=item close()

Close socket connection.

=cut

sub close {
	my $self = shift;

	if ($self->{'tacacsserver'})
	{	
		if (!close($self->{'tacacsserver'})) { warn "Error closing IO socket!\n" };
		undef $self->{'tacacsserver'};
	}
}

=item init_tacacs_session()

Inititalize socket connection to tacacs server.

=cut

sub init_tacacs_session
{
	my $self = shift;

	my $remote;
	$remote = IO::Socket::INET->new(Proto => "tcp", PeerAddr => $self->{'host'},
					PeerPort => $self->{'port'}, Timeout => $self->{'timeout'});
	if (!$remote) { die("unable to connect to $host:$port\n"); }

	$self->{'tacacsserver'} = $remote;
	$self->{'session_id'} = int(rand(2 ** 32 - 1));	#2 ** 32 - 1
}

=item authenticate(username, password, authen_type)

username		- tacacs+ username
password		- tacacs+ user password
authen_type		- TAC_PLUS_AUTHEN_TYPE_ASCII | TAC_PLUS_AUTHEN_TYPE_PAP

=cut

sub authenticate {
	my ($self,$username,$password,$authen_type) = @_;

	eval {
		#tacacs+ START packet
		my $pkt;

		if ($authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII)
		{
			$pkt = Net::TacacsPlus::Packet->new(
				#header
				'type' => TAC_PLUS_AUTHEN,
				'seq_no' => $self->{'seq_no'},
				'flags' => 0,
				'session_id' => $self->{'session_id'},
				'authen_type' => $authen_type,
				#start
				'action' => TAC_PLUS_AUTHEN_LOGIN,
				'key' => $self->{'key'},
				'rem_addr' => inet_ntoa($self->{'tacacsserver'}->sockaddr)
				);
		} elsif ($authen_type == TAC_PLUS_AUTHEN_TYPE_PAP)
		{
			$pkt = Net::TacacsPlus::Packet->new(
				#header
				'type' => TAC_PLUS_AUTHEN,
				'seq_no' => $self->{'seq_no'},
				'flags' => 0,
				'session_id' => $self->{'session_id'},
				'authen_type' => $authen_type,
				'minor_version' => 1,
				#start
				'action' => TAC_PLUS_AUTHEN_LOGIN,
				'key' => $self->{'key'},
				'user' => $username,
				'password' => $password,
				'rem_addr' => inet_ntoa($self->{'tacacsserver'}->sockaddr)
				);
		} else { die ('unsupported "authen_type" '.$authen_type.'.'); }

		$pkt->send($self->{'tacacsserver'});

		#loop through REPLY/CONNTINUE packets
		do {
			#receive reply packet
			my $raw_reply;
			$self->{'tacacsserver'}->recv($raw_reply,1024);
			die "reply read error ($raw_reply)." if not length($raw_reply);

			$reply = Net::TacacsPlus::Packet->new(
						'raw_authen_reply' => $raw_reply,
						'key' => $self->{'key'},
						);

			Net::TacacsPlus::Packet->check_reply($pkt,$reply);

			$status=$reply->status();
			if ($status == TAC_PLUS_AUTHEN_STATUS_GETUSER)
			{
				$pkt = Net::TacacsPlus::Packet->new(
					#header
					'type' => TAC_PLUS_AUTHEN,
					'seq_no' => $reply->seq_no()+1,
					'session_id' => $self->{'session_id'},
					#continue
					'user_msg' => $username,
					'data' => '',
					'key' => $self->{'key'},
					);
				$pkt->send($self->{'tacacsserver'});
			} elsif ($status == TAC_PLUS_AUTHEN_STATUS_GETPASS)
			{
				$pkt = Net::TacacsPlus::Packet->new(
					#header
					'type' => TAC_PLUS_AUTHEN,
					'seq_no' => $reply->seq_no()+1,
					'session_id' => $self->{'session_id'},
					#continue
					'user_msg' => $password,
					'data' => '',
					'key' => $self->{'key'},
					);
				$pkt->send($self->{'tacacsserver'});
			} elsif ($status == TAC_PLUS_AUTHEN_STATUS_ERROR)
			{
				die('authen status - error');
			} elsif (($status == TAC_PLUS_AUTHEN_STATUS_FAIL) || ($status == TAC_PLUS_AUTHEN_STATUS_PASS))
			{
			} else
			{
				die('unhandled status '.(0 + $status).'');
			}
		} while (($status != TAC_PLUS_AUTHEN_STATUS_FAIL) && ($status != TAC_PLUS_AUTHEN_STATUS_PASS))
	};
	if ($@)
	{
		warn 'communication error "'.$@.'"\n';
		$errmsg=$@;
		return undef;
	}

	return undef if $status == TAC_PLUS_AUTHEN_STATUS_FAIL;

	return 1;
}

sub DESTROY {
	my $self = shift;

	$self->close();
}

return 1;

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Jozef Kutej

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut

package Net::TacacsPlus::Packet::AuthenReplyBody;

=head1 NAME

Net::TacacsPlus::Packet::AuthenReplyBody;

=head1 DESCRIPTION

7.  The authentication REPLY packet body

The TACACS+ daemon sends only one type of  authentication  packet  (a
REPLY packet) to the client. The REPLY packet body looks as follows:

	 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
	
	+----------------+----------------+----------------+----------------+
	|     status     |      flags     |        server_msg len           |
	+----------------+----------------+----------------+----------------+
	|           data len              |        server_msg ...
	+----------------+----------------+----------------+----------------+
	|           data ...
	+----------------+----------------+

=cut


our $VERSION = '1.03';

use strict;
use warnings;

use 5.006;
use Net::TacacsPlus::Constants 1.03;
use Carp::Clan;

=head1 METHODS

=over 4

=item new( somekey => somevalue)

Construct tacacs+ authentication packet body object

Parameters:

	'raw_body': raw body

=cut

sub new {
	my $class = shift;
	my %params = @_;
	my $self = {};
	
	bless $self, $class;

	if ($params{'raw_body'})
	{
		$self->decode($params{'raw_body'});	
		return $self;
	}

	return $self;
}

=item decode($raw_data)

Extract $server_msg and data from raw packet.

=cut

sub decode {
	my ($self, $raw_data) = @_;
	
	my ($server_msg_len,$data_len,$payload);
	
	( $self->{'status'},
	$self->{'flags'},
	$server_msg_len,
	$data_len,
	$payload,
	) = unpack("CCnnA*", $raw_data);

	$payload = '' if not defined $payload; #payload can be empty

	($self->{'server_msg'},
	$self->{'data'}) = unpack("A".$server_msg_len."A".$data_len,$payload);
}

=item server_msg()

Return server message. 

=cut

sub server_msg {
	my $self = shift;

	return $self->{'server_msg'};
}

=item status()

Return status.

=cut

sub status {
	my $self = shift;

	return $self->{'status'};
}

1;

=back

=cut


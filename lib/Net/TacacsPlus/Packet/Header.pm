package Net::TacacsPlus::Packet::Header;

=head1 NAME

Net::TacacsPlus::Packet::Header

=head1 DESCRIPTION

3.  The TACACS+ packet header

All TACACS+ packets always begin with the following 12  byte  header.
The  header  is  always  cleartext and describes the remainder of the
packet:


	 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
	
	+----------------+----------------+----------------+----------------+
	|major  | minor  |                |                |                |
	|version| version|      type      |     seq_no     |   flags        |
	+----------------+----------------+----------------+----------------+
	|                                                                   |
	|                            session_id                             |
	+----------------+----------------+----------------+----------------+
	|                                                                   |
	|                              length                               |
	+----------------+----------------+----------------+----------------+

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

Construct tacacs+ packet header object

1. if constructing from parameters:

	'version': protocol version
	'type': TAC_PLUS_(AUTHEN|AUTHOR|ACCT) 
	'seq_no': sequencenumber
	'flags': TAC_PLUS_(UNENCRYPTED_FLAG|SINGLE_CONNECT_FLAG)
	'session_id': session id

2. if constructing from raw packet

	'raw_header': raw packet

=cut

sub new {
	my $class = shift;
	my %params = @_;
	my $self = {};
	
	bless $self, $class;

	if ($params{'raw_header'})
	{
		$self->decode($params{'raw_header'});	
		return $self;
	}

	$self->{'version'} = $params{'version'};
	$self->{'type'} = $params{'type'};
	$self->{'seq_no'} = $params{'seq_no'} ? $params{'seq_no'} : 1;
	$self->{'flags'} = $params{'flags'} ? $params{'flags'} : 0;
	carp("session_id must be set!") unless $params{'session_id'};
	$self->{'session_id'} = $params{'session_id'};

	return $self;
}

=item decode($raw_data)

Decode $raw_data to version, type, seq_no, flags, session_id, length

=cut

sub decode {
	my ($self, $raw_data) = @_;
	
	( $self->{'version'},
	$self->{'type'},
	$self->{'seq_no'},
	$self->{'flags'},
	$self->{'session_id'},
	$self->{'length'} ) = unpack("CCCCNN", $raw_data);
	
}

=item raw()

returns raw binary representation of header.

B<NOTE> For complete binary header, length of body must be
added.

=cut

sub raw {
	my $self = shift;

	return pack("CCCCN",
			$self->{'version'},
			$self->{'type'},
			$self->{'seq_no'},
			$self->{'flags'},
			$self->{'session_id'},
			);
}

=item seq_no()

Return header sequence number.

=cut

sub seq_no() {
	my $self = shift;

	return $self->{'seq_no'};
}

=item session_id()

Return packet session_id.

=cut

sub session_id {
	my $self = shift;

	return $self->{'session_id'};
}

=item version()

Return packet version.

=cut

sub version {
	my $self = shift;

	return $self->{'version'};
}



=item flags()

Return packet flags.

=cut

sub flags {
	my $self = shift;

	return $self->{'flags'};
}

=item type()

Return packet type.

=cut

sub type()
{
	my $self = shift;

	return $self->{'type'};
}

1;

=back

=cut

1;

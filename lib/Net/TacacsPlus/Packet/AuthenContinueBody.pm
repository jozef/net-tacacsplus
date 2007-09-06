package Net::TacacsPlus::Packet::AuthenContinueBody;

=head1 NAME

Net::TacacsPlus::Packet::AuthenContinueBody;

=head1 DESCRIPTION

	8.  The authentication CONTINUE packet body
	
	This packet is sent from the NAS to the daemon following the  receipt
	of a REPLY packet.
	
	
	      1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
	
	     +----------------+----------------+----------------+----------------+
	     |          user_msg len           |            data len             |
	     +----------------+----------------+----------------+----------------+
	     |     flags      |  user_msg ...
	     +----------------+----------------+----------------+----------------+
	     |    data ...
	     +----------------+

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

Construct tacacs+ authentication CONTINUE packet body object

Parameters:

	'user_msg': user message requested by server
	'data': data requested by server
	'flags': TAC_PLUS_CONTINUE_FLAG_ABORT

=cut

sub new() {
	my $class = shift;
	my %params = @_;
	my $self = {};
	
	bless $self, $class;

	$self->{'user_msg'} = $params{'user_msg'};
	$self->{'data'} = $params{'data'};
	$self->{'flags'} = $params{'continue_flags'} ? $params{'continue_flags'} : 0;
#	$self->{''} = $params{''} ? $params{''} : TAC_PLUS_;

	return $self;
}

=item raw()

Return binary data of packet body.

=cut

sub raw {
	my $self = shift;

	my $body = pack("nnC",
		length($self->{'user_msg'}),
		length($self->{'data'}),
		$self->{'flags'},
	).$self->{'user_msg'}.$self->{'data'};

	return $body;
}

1;

=back

=cut

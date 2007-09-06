package Net::TacacsPlus::Packet::AuthenStartBody;

=head1 NAME

Net::TacacsPlus::PacketAuthenStartBody;

=head1 DESCRIPTION

The authentication START packet body

	 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

	+----------------+----------------+----------------+----------------+
	|    action      |    priv_lvl    |  authen_type   |     service    |
	+----------------+----------------+----------------+----------------+
	|    user len    |    port len    |  rem_addr len  |    data len    |
	+----------------+----------------+----------------+----------------+
	|    user ...
	+----------------+----------------+----------------+----------------+
	|    port ...
	+----------------+----------------+----------------+----------------+
	|    rem_addr ...
	+----------------+----------------+----------------+----------------+
	|    data...
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

Construct tacacs+ authentication START packet body object

Parameters:

	action: TAC_PLUS_AUTHEN_[^_]+$
	priv_lvl: TAC_PLUS_PRIV_LVL_*
	authen_type: TAC_PLUS_AUTHEN_TYPE_*
	service: TAC_PLUS_AUTHEN_SVC_*
	user: username
	password: password
	port: port dft. 'Virtual00'
	rem_addr: our ip address

=cut

sub new {
	my $class = shift;
	my %params = @_;
	my $self = {};
	
	bless $self, $class;

	$self->{'action'} = $params{'action'};
	$self->{'priv_lvl'} = $params{'priv_lvl'} ? $params{'priv_lvl'} : TAC_PLUS_PRIV_LVL_MIN;
	$self->{'authen_type'} = $params{'authen_type'};
	$self->{'service'} = $params{'service'} ? $params{'service'} : TAC_PLUS_AUTHEN_SVC_LOGIN;
	$self->{'user'} = $params{'user'};
	$self->{'password'} = exists $params{'password'} ? $params{'password'} : '';
	$self->{'port'} = $params{'port'} ? $params{'port'} : 'Virtual00';
	$self->{'rem_addr'} = $params{'rem_addr'} ? $params{'rem_addr'} : '127.0.0.1';
#	$self->{''} = $params{''} ? $params{''} : TAC_PLUS_;

	return $self;
}

=item raw()

Return binary data of packet body.

=cut

sub raw {
	my $self = shift;

	my $body = pack("CCCCCCCC",
		$self->{'action'},
		$self->{'priv_lvl'},
		$self->{'authen_type'},
		$self->{'service'},
		length($self->{'user'}),
		length($self->{'port'}),
		length($self->{'rem_addr'}),
		length($self->{'password'}),
	).$self->{'user'}.$self->{'port'}.$self->{'rem_addr'}.$self->{'password'};

	return $body;
}

1;

=back

=cut

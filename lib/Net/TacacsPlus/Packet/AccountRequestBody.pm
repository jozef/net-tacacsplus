package Net::TacacsPlus::Packet::AccountRequestBody;

=head1 NAME

Net::TacacsPlus::Packet::AccountRequestBody;

=head1 DESCRIPTION

The account REQUEST packet body


         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

        +----------------+----------------+----------------+----------------+
        |      flags     |  authen_method |    priv_lvl    |  authen_type   |
        +----------------+----------------+----------------+----------------+
        | authen_service |    user len    |    port len    |  rem_addr len  |
        +----------------+----------------+----------------+----------------+
        |    arg_cnt     |   arg 1 len    |   arg 2 len    |      ...       |
        +----------------+----------------+----------------+----------------+
        |   arg N len    |    user ...
        +----------------+----------------+----------------+----------------+
        |   port ...
        +----------------+----------------+----------------+----------------+
        |   rem_addr ...
        +----------------+----------------+----------------+----------------+
        |   arg 1 ...
        +----------------+----------------+----------------+----------------+
        |   arg 2 ...
        +----------------+----------------+----------------+----------------+
        |   ...
        +----------------+----------------+----------------+----------------+
        |   arg N ...
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

Construct tacacs+ accounting REQUEST packet body object

Parameters:

	acct_flags: TAC_PLUS_ACCT_FLAG_*
	authen_method: TAC_PLUS_AUTHEN_METH_*
	priv_lvl: TAC_PLUS_PRIV_LVL_*
	authen_type: TAC_PLUS_AUTHEN_TYPE_*
	service: TAC_PLUS_AUTHEN_SVC_*
	user: username
	port: port dft. 'Virtual00'
	rem_addr: our ip address
	args: args arrayref

=cut

sub new()
{
	my $class = shift;
	my %params = @_;
	my $self = {};
	
	bless $self, $class;

	$self->{'flags'} = $params{'acct_flags'} ? $params{'acct_flags'} : TAC_PLUS_ACCT_FLAG_STOP;
	$self->{'authen_method'} = $params{'authen_method'} ? $params{'authen_method'} : TAC_PLUS_AUTHEN_METH_TACACSPLUS;
	$self->{'priv_lvl'} = $params{'priv_lvl'} ? $params{'priv_lvl'} : TAC_PLUS_PRIV_LVL_MIN;
	$self->{'authen_type'} = $params{'authen_type'} ? $params{'authen_type'} : TAC_PLUS_AUTHEN_TYPE_ASCII;
	$self->{'authen_service'} = $params{'service'} ? $params{'service'} : TAC_PLUS_AUTHEN_SVC_LOGIN;
	$self->{'user'} = $params{'user'};
	$self->{'port'} = $params{'port'} ? $params{'port'} : 'Virtual00';
	$self->{'rem_addr'} = $params{'rem_addr'} ? $params{'rem_addr'} : '127.0.0.1';
	$self->{'args'} = $params{'args'};

	return $self;
}

=item raw()

Return binary data of packet body.

=cut

sub raw
{
	my $self = shift;

	my $body = pack("CCCCCCCCC",
		$self->{'flags'},
		$self->{'authen_method'},
		$self->{'priv_lvl'},
		$self->{'authen_type'},
		$self->{'authen_service'},
		length($self->{'user'}),
		length($self->{'port'}),
		length($self->{'rem_addr'}),
		scalar(@{$self->{'args'}}),
	);
	foreach my $arg (@{$self->{'args'}})
	{
		$body .= pack("C", length($arg));
	}
	$body .= $self->{'user'}.$self->{'port'}.$self->{'rem_addr'}.join('', @{$self->{'args'}});

	return $body;
}

1;

=back

=cut

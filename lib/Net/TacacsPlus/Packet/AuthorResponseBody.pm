package Net::TacacsPlus::Packet::AuthorResponseBody;

=head1 NAME

Net::TacacsPlus::Packet::AuthorResponseBody;

=head1 DESCRIPTION

The authorization RESPONSE packet body



         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

        +----------------+----------------+----------------+----------------+
        |    status      |     arg_cnt    |         server_msg len          |
        +----------------+----------------+----------------+----------------+
        +            data len             |    arg 1 len   |    arg 2 len   |
        +----------------+----------------+----------------+----------------+
        |      ...       |   arg N len    |         server_msg ...
        +----------------+----------------+----------------+----------------+
        |   data ...
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

Construct tacacs+ authorization response body object

Parameters:

	'raw_body': raw body

=cut

sub new()
{
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

Extract status, server_msg, data and arguments from raw packet.

=cut

sub decode($)
{
	my ($self, $raw_data) = @_;
	
	my ($server_msg_len,$arg_cnt,@arg_lengths,$data_len,$offset,@args);
	
	( $self->{'status'},
	$arg_cnt,
	$server_msg_len,
	$data_len,
	) = unpack("CCnn", $raw_data);
	$offset = 6;
	
	@arg_lengths = unpack("x$offset " . ("C" x $arg_cnt), $raw_data);
	$offset += $arg_cnt;

	($self->{'server_msg'}, $self->{'data'}) =
		unpack("x$offset A".$server_msg_len."A".$data_len, $raw_data);
	$offset += $server_msg_len + $data_len;

	foreach my $arglen (@arg_lengths)
	{
		push(@args, unpack("x$offset A$arglen", $raw_data));
		$offset += $arglen;
	}
		
	$self->{'args'} = \@args;
}

=item server_msg()

Return server message.

=cut

sub server_msg()
{
	my $self = shift;

	return $self->{'server_msg'};
}

=item status()

Return status.

=cut

sub status()
{
	my $self = shift;

	return $self->{'status'};
}

=item args()

Return arguments returned by server in authorization response packet.

=cut

sub args()
{
	my $self = shift;

	return $self->{'args'};
}

1;

=back

=cut

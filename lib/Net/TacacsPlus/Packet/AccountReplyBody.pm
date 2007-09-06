package Net::TacacsPlus::Packet::AccountReplyBody;

=head1 NAME

Net::TacacsPlus::Packet::AccountReplyBody;

=head1 DESCRIPTION

The accounting REPLY packet body

   The response to an accounting message is used to  indicate  that  the
   accounting   function  on  the  daemon  has  completed  and  securely
   committed the record. This provides  the  client  the  best  possible
   guarantee that the data is indeed logged.



         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

        +----------------+----------------+----------------+----------------+
        |         server_msg len          |            data len             |
        +----------------+----------------+----------------+----------------+
        |     status     |         server_msg ...
        +----------------+----------------+----------------+----------------+
        |     data ...
        +----------------+

=cut


our $VERSION = '1.04';

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

Extract status, server_msg and data from raw packet.

=cut

sub decode($)
{
	my ($self, $raw_data) = @_;
	
	my ($server_msg_len,$data_len,$payload);
	
	( $server_msg_len,
	$data_len,
	$self->{'status'},
	$payload,
	) = unpack("nnCA*", $raw_data);
	
	($self->{'server_msg'},
	$self->{'data'}) = unpack("A".$server_msg_len."A".$data_len,$payload);
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

1;

=back

=cut

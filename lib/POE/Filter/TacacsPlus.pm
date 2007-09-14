package POE::Filter::TacacsPlus;

=head1 NAME

POE::Filter::TacacsPlus - TacacsPlus packet filter

=cut

use Net::TacacsPlus::Packet 1.05;


=head1 METHODS

=over 4

=item new()

Construct a filter object.

=cut

sub new {
	my $class = shift;
	
	my $self = {
	};
	
	bless $self, $class;
	
	return $self;
}

=item get(@raw_packets)

Transforms raw packets to the Net::TacacsPlus::Packet object.

=cut

sub get {
	my $self = shift;
	
	my @tacacs_packets;
	foreach my $raw (@_) {
		push(@tacacs_packets, Net::TacacsPlus::Packet->new('raw' => $raw));
	}
	
	return @tacacs_packets;
}

=item pub(@packet_objects)

Transforms Net::TacacsPlus::Packet to the binary packet form.

=cut

sub put {
	my $self = shift;
	
	my @tacacs_raw_packets;
	foreach my $packet (@_) {
		push(@tacacs_raw_packets, $packet->raw);
	}
	
	return @tacacs_raw_packets;
}

=back

=cut

1;

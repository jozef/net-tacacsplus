package POE::Filter::TacacsPlus;

sub new {
	my $class = shift;
	my $type  = shift;
	
	my $self = {
	};
	
	bless $self, $class;
	
	return $self;
}

=head1 METHODS

=over 4

=item get(@raw_packets)

Transforms raw packets to the Net::TacacsPlus::Packet object.

=cut

sub get {
	my $self = shift;
	
	
}

=item pub(@packet_objects)

Transforms Net::TacacsPlus::Packet to the binary packet form.

=cut

sub put {
	my $self = shift;
}

=back

=cut

1;

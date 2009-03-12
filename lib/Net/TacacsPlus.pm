package Net::TacacsPlus;

=head1 NAME

Net::TacacsPlus - Tacacs+ library

=head1 SYNOPSYS

	use Net::TacacsPlus qw{ tacacs_client };
	
	my $client = tacacs_client(
		'host' => 'tacacs.server',
		'key'  => 'secret',
	);

=head1 DESCRIPTION

Tacacs+ client implemented by L<Net::TacacsPlus::Client>.
Tacacs+ server (pap auth only) implemented by L<POE::Component::Server::TacacsPlus>.

=cut

our $VERSION = '1.08';

use strict;
use warnings;

use Net::TacacsPlus::Client 1.06;

use Exporter;
use 5.006;

our @ISA = ('Exporter');
our @EXPORT_OK = ('tacacs_client');

=head1 FUNCTIONS

=over 4

=item tacacs_client(@arg)

Returns L<Net::TacacsPlus::Client> object created with @arg. 

=cut

sub tacacs_client {
	my @arg = @_;
	
	return Net::TacacsPlus::Client->new(@arg);
}

=back

=cut

1;

=head1 AUTHOR

Jozef Kutej - E<lt>jkutej@cpan.orgE<gt>

Authorization and Accounting contributed by Rubio Vaughan E<lt>rubio@passim.netE<gt>

=head1 SEE ALSO

tac-rfc.1.78.txt

=cut

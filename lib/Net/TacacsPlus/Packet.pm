=head1 NAME

Net::TacacsPlus::Packet - Tacacs+ packet object

=head1 SYNOPSIS
	
	# construct authentication START packet
	
	$pkt = Net::TacacsPlus::Packet->new(
		#header
		'type' => TAC_PLUS_AUTHEN,
		'seq_no' => 1,
		'flags' => 0,
		'session_id' => $session_id,
		#start
		'action' => TAC_PLUS_AUTHEN_LOGIN,
		'authen_type' => TAC_PLUS_AUTHEN_TYPE_(ASCII|PAP),
		'key' => $secret,
		);
	
	
	# construct authentication CONTINUE packet
	
	$pkt = Net::TacacsPlus::Packet->new(
		#header
		'type' => TAC_PLUS_AUTHEN,
		'seq_no' => 3,
		'session_id' => $session_id,
		#continue
		'user_msg' => $username,
		'data' => '',
		'key' => $secret,
		);
	
	# construct authentication REPLY packet from received raw packet
	
	$reply = Net::TacacsPlus::Packet->new(
			'type' => TAC_PLUS_AUTHEN,
			'raw' => $raw_reply,
			'key' => $secret,
			);

	# construct authorization REQUEST packet

	$pkt = Net::TacacsPlus::Packet->new(
		#header
		'type' => TAC_PLUS_AUTHOR,
		'seq_no' => 1,
		'session_id' => $session_id,
		#request
		'user' => $username,
		'args' => $args, # arrayref
		'key' => $secret,
		);

	# construct authorization RESPONSE packet from received raw packet

	$response = Net::TacacsPlus::Packet->new(
			'type' => TAC_PLUS_AUTHOR,
			'raw' => $raw_reply,
			'key' => $secret,
			);

	# construct accounting REQUEST packet

	$pkt = Net::TacacsPlus::Packet->new(
		#header
		'type' => TAC_PLUS_ACCT,
		'seq_no' => 1,
		'session_id' => $session_id,
		#request
		'acct_flags' => TAC_PLUS_ACCT_FLAG_*,
		'user' => $username,
		'args' => $args, # arrayref
		'key' => $secret,
		);

	# construct accounting REPLY packet from received raw packet

	$reply = Net::TacacsPlus::Packet->new(
			'type' => TAC_PLUS_ACCT,
			'raw' => $raw_reply,
			'key' => $secret,
			);

=head1 DESCRIPTION

Library to create and manipulate Tacacs+ packets. Object can be build
from parameters or from raw received packet.

=head1 AUTHOR

Jozef Kutej E<lt>jozef@kutej.netE<gt>

Authorization and Accounting contributed by Rubio Vaughan <lt>rubio@passim.net<gt>

=head1 VERSION

1.03

=head1 SEE ALSO

tac-rfc.1.78.txt, Net::TacacsPlus::Client

=cut

package Net::TacacsPlus::Packet;

our $VERSION = '1.03';

use strict;
use warnings;

use 5.006;
use Net::TacacsPlus::Constants 1.03;
use Carp::Clan;
use Digest::MD5 ('md5');
use Math::XOR ('xor_buf');

=head1 METHODS

=over 4

=item new( somekey => somevalue )

1. if constructing from parameters need this parameters:

for header:

	'type': TAC_PLUS_(AUTHEN|AUTHOR|ACCT) 
	'seq_no': sequencenumber
	'flags': TAC_PLUS_(UNENCRYPTED_FLAG|SINGLE_CONNECT_FLAG)
	'session_id': session id

for authentication START body:

	'action' => TAC_PLUS_AUTHEN_(LOGIN|CHPASS|SENDPASS|SENDAUTH)
	'authen_type' => TAC_PLUS_AUTHEN_TYPE_(ASCII|PAP)
	'key': encryption key

for authentication CONTINUE body:	
	'user_msg': msg required by server
	'data' => data required by server
    'key': encryption key

for authorization REQUEST body:
	'user': username
	'args': authorization arguments
	'key': encryption key

for accounting REQUEST body:
	'acct_flags': TAC_PLUS_ACCT_FLAG_(MORE|START|STOP|WATCHDOG)
	'user': username
	'args': authorization arguments
	'key': encryption key

2. if constructing from received raw packet

for AUTHEN reply, AUTHOR response and ACCT reply:

	'type': TAC_PLUS_(AUTHEN|AUTHOR|ACCT)
	'raw': raw packet
	'key': encryption key

=cut

sub new {
	my $class = shift;
	my %params = @_;
	my $self = {};

	bless $self, $class;

	#save encryption key
	$self->{'key'} = $params{'key'};

	if (!$params{'type'}) { die("TacacsPlus packet type is required parameter."); }
	$self->{'type'} = $params{'type'};

	#create object from raw packet
	if ($params{'raw'})
	{
		$self->decode_reply($params{'raw'});
		
		return $self;	
	}

	#compute version byte
	$params{'major_version'} = $params{'major_version'} ? $params{'major_version'} : TAC_PLUS_MAJOR_VER;
	$params{'minor_version'} = $params{'minor_version'} ? $params{'minor_version'} : TAC_PLUS_MINOR_VER_DEFAULT;
	$params{'version'} = $params{'major_version'}*0x10+$params{'minor_version'};
	
	$self->{'header'} = Net::TacacsPlus::PacketHeader->new(%params);

	if ($params{'type'} == TAC_PLUS_AUTHEN)
	{
		if ($params{'action'})				#if action is set it is the first START packet
		{
			$self->{'body'} = Net::TacacsPlus::PacketAuthenStartBody->new(%params);
		} elsif ($params{'user_msg'})		#else it is CONTINUE
		{
			$self->{'body'} = Net::TacacsPlus::PacketAuthenContinueBody->new(%params);
		} else { die("unknown request for body creation"); }
	} elsif ($params{'type'} == TAC_PLUS_AUTHOR)
	{
		$self->{'body'} = Net::TacacsPlus::PacketAuthorRequestBody->new(%params);
	} elsif ($params{'type'} == TAC_PLUS_ACCT)
	{
		$self->{'body'} = Net::TacacsPlus::PacketAccountRequestBody->new(%params);
	} else
	{
		die('TacacsPlus packet type '.$params{'type'}.' unsupported.');
	}

	return $self;
}

=item check_reply($snd, $rcv)

compare send and reply packet for errors

$snd - packet object that was send
$rcv - packet object that was received afterwards	

checks sequence number, session id, version and flags

=cut

sub check_reply {
	my ($self, $snd, $rcv) = @_;
	
	if (($snd->seq_no() + 1) != ($rcv->seq_no())) { croak("seq_no mismash"); }
	if (($snd->session_id()) != ($rcv->session_id())) { croak("session_id mismash"); }
	if (($snd->version()) != ($rcv->version())) { croak("version mismash"); }	
	if (($snd->flags()) != ($rcv->flags())) { croak("flags mismash"); }	
}

=item decode_reply($raw_pkt)

From raw packet received create reply object:
Net::TacacsPlus::PacketAuthenReplyBody or
Net::TacacsPlus::PacketAuthorResponseBody or
Net::TacacsPlus::PacketAccountReplyBody

=cut

sub decode_reply {
	my ($self, $raw_pkt) = @_;
	
	my ($raw_header,$raw_body) = unpack("A".TAC_PLUS_HEADER_SIZE."A*",$raw_pkt);
	
	$self->{'header'} = Net::TacacsPlus::PacketHeader->new('raw_header' => $raw_header);
	$self->{'seq_no'} = $self->{'header'}->seq_no();
	$self->{'session_id'} = $self->{'header'}->session_id();
	$self->{'version'} = $self->{'header'}->version();
	$self->{'type'} = $self->{'header'}->type();

	$raw_body = $self->raw_xor_body($raw_body);
	if ($self->{'type'} == TAC_PLUS_AUTHEN)
	{
		$self->{'body'} = Net::TacacsPlus::PacketAuthenReplyBody->new('raw_body' => $raw_body);	
	} elsif ($self->{'type'} == TAC_PLUS_AUTHOR)
	{
		$self->{'body'} = Net::TacacsPlus::PacketAuthorResponseBody->new('raw_body' => $raw_body);
	} elsif ($self->{'type'} == TAC_PLUS_ACCT)
	{
		$self->{'body'} = Net::TacacsPlus::PacketAccountReplyBody->new('raw_body' => $raw_body);
	} else
	{
		die('TacacsPlus packet type '.$self->{'type'}.' unsupported.');
	}
}

=item raw( )

return binary representation of whole packet.

=cut

sub raw {
	my $self = shift;
	my $key = shift;
	
	my $header=$self->{'header'}->raw();
	my $body=$self->raw_xor_body($self->{'body'}->raw());
	$header=$header.pack("N",length($body));

	return $header.$body;
}

=item raw_xor_body($data)

XOR $data by pseudo pas.

=cut

sub raw_xor_body {
	my ($self,$data) = @_;

	return $data if not $self->{'key'};

	my $pseudo_pad=compute_pseudo_pad(
					$self->session_id(),
					$self->{'key'},
					$self->version(),
					$self->seq_no(),
					length($data),
					);
	
	$data=xor_buf($data,$pseudo_pad);

	return $data;
}

=item compute_pseudo_pad( $sess_id,$key,$version,$seq_no,$length )

compute md5 hash from parameters truncated to $length

	pseudo_pad = {MD5_1 [,MD5_2 [ ... ,MD5_n]]} truncated to len(data)

The first MD5 hash is generated by concatenating the session_id, the
secret key, the version number and the sequence number and then running
MD5 over that stream. All of those input values are available in the
packet header, except for the secret key which is a shared secret
between the TACACS+ client and daemon.

=cut

sub compute_pseudo_pad {
	my ( $sess_id,$key,$version,$seq_no,$length ) = @_;

	my ( $data,$md5hash, $hash, $md5len );

	$data = pack("NA*CC",$sess_id,$key,$version,$seq_no);
	
	$md5len = 0;
	$hash = '';
	$md5hash = '';

	while ( $md5len < $length ) {
		$md5hash = md5($data.$md5hash);
		$hash .= $md5hash;
		$md5len+=16;
	}

	return substr ( $hash, 0, $length );

}

=item server_msg( )

returns last server msg

=cut

sub server_msg() {
	my $self = shift;
	
	return $self->{'body'}->server_msg();
}

=item seq_no()

Return packet sequence number.

=cut

sub seq_no() {
	my $self = shift;
	
	return $self->{'header'}->seq_no();
}

=item session_id()

Return packet session id.

=cut

sub session_id() {
	my $self = shift;
	
	return $self->{'header'}->session_id();
}

=item version()

Return version from packet header

=cut

sub version() {
	my $self = shift;
	
	return $self->{'header'}->version();
}

=item flags()

Return flags from packet header.

=cut

sub flags() {
	my $self = shift;
	
	return $self->{'header'}->flags();
}

=item args()

Return arguments returned by server in authorization response packet.

=cut

sub args()
{
	my $self = shift;
	
	if($self->{'type'} == TAC_PLUS_AUTHOR)
	{
		return $self->{'body'}->args();
	} else
	{
		die("Arguments only available for authorization response packets")
	}
}

=item status( )

returns status of packet. it is used in REPLY packets received from
server.

status is one of:

	TAC_PLUS_AUTHEN_STATUS_PASS        => 0x01,
	TAC_PLUS_AUTHEN_STATUS_FAIL        => 0x02,
	TAC_PLUS_AUTHEN_STATUS_GETDATA     => 0x03,
	TAC_PLUS_AUTHEN_STATUS_GETUSER     => 0x04,
	TAC_PLUS_AUTHEN_STATUS_GETPASS     => 0x05,
	TAC_PLUS_AUTHEN_STATUS_RESTART     => 0x06,
	TAC_PLUS_AUTHEN_STATUS_ERROR       => 0x07,
	TAC_PLUS_AUTHEN_STATUS_FOLLOW      => 0x21,
	TAC_PLUS_AUTHOR_STATUS_PASS_ADD    => 0x01,
	TAC_PLUS_AUTHOR_STATUS_PASS_REPL   => 0x02,
	TAC_PLUS_AUTHOR_STATUS_FAIL        => 0x10,
	TAC_PLUS_AUTHOR_STATUS_ERROR       => 0x11,
	TAC_PLUS_AUTHOR_STATUS_FOLLOW      => 0x21,
	TAC_PLUS_ACCT_STATUS_SUCCESS       => 0x01,
	TAC_PLUS_ACCT_STATUS_ERROR         => 0x02,
	TAC_PLUS_ACCT_STATUS_FOLLOW        => 0x21,

=cut

sub status() {
	my $self = shift;
	
	return $self->{'body'}->status();
}

=item send()

Send out packet.

=cut

sub send() {
	my ($self, $remote) = @_;

	my $raw_pkt = $self->raw();
	
	my $bytes = $remote->send($raw_pkt);
	croak("error sending packet!") if ($bytes != length($raw_pkt));
	
	return $bytes;
}

1;

=back
=cut






=head1 NAME

Net::TacacsPlus::PacketHeader

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

package Net::TacacsPlus::PacketHeader;

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









=head1 NAME

Net::TacacsPlus::PacketAuthenReplyBody;

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

package Net::TacacsPlus::PacketAuthenReplyBody;

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

package Net::TacacsPlus::PacketAuthenStartBody;

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
	$self->{'password'} = $params{'password'};
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






=head1 NAME

Net::TacacsPlus::PacketAuthenContinueBody;

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

package Net::TacacsPlus::PacketAuthenContinueBody;

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

=head1 NAME

Net::TacacsPlus::PacketAuthorRequestBody;

=head1 DESCRIPTION

The authorization REQUEST packet body

         1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

        +----------------+----------------+----------------+----------------+
        |  authen_method |    priv_lvl    |  authen_type   | authen_service |
        +----------------+----------------+----------------+----------------+
        |    user len    |    port len    |  rem_addr len  |    arg_cnt     |
        +----------------+----------------+----------------+----------------+
        |   arg 1 len    |   arg 2 len    |      ...       |   arg N len    |
        +----------------+----------------+----------------+----------------+
        |   user ...
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

package Net::TacacsPlus::PacketAuthorRequestBody;

our $VERSION = '1.03';

use strict;
use warnings;

use 5.006;
use Net::TacacsPlus::Constants 1.03;
use Carp::Clan;

=head1 METHODS

=over 4

=item new( somekey => somevalue)

Construct tacacs+ authorization REQUEST packet body object

Parameters:

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

	my $body = pack("CCCCCCCC",
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


=head1 NAME

Net::TacacsPlus::PacketAuthorResponseBody;

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

package Net::TacacsPlus::PacketAuthorResponseBody;

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


=head1 NAME

Net::TacacsPlus::PacketAccountRequestBody;

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

package Net::TacacsPlus::PacketAccountRequestBody;

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


=head1 NAME

Net::TacacsPlus::PacketAccountReplyBody;

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

package Net::TacacsPlus::PacketAccountReplyBody;

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


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Jozef Kutej

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut

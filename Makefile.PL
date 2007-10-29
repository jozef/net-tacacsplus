use 5.006;
use ExtUtils::MakeMaker;

WriteMakefile(
	NAME         => 'Net::TacacsPlus',
	VERSION_FROM => 'lib/Net/TacacsPlus.pm', # finds $VERSION
	PREREQ_PM    => {
		Math::XOR     => 0,
		Digest::MD5   => 0,
		Carp::Clan    => 0,
		IO::Socket    => 0,
		Test::More    => 0,
		Test::Differences
		              => 0,
		Class::Accessor::Fast
		              => 0,
		Log::Log4perl => 0,
		POE           => 0,
	},
	($] >= 5.005 ?     ## Add these new keywords supported since 5.005
		(ABSTRACT_FROM => 'lib/Net/TacacsPlus.pm', # retrieve abstract from module
		AUTHOR         => 'Jozef Kutej <jozef@kutej.net>') : ()),
	(MM->can('signature_target') ? (SIGN => 1) : ()),
	LICENSE => 'perl',
);

use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::TacacsPlus::Client',
    VERSION_FROM      => 'lib/Net/TacacsPlus.pm', # finds $VERSION
    PREREQ_PM         => {
    	Math::XOR	  => 0,
    	Digest::MD5   => 0,
	   	Carp::Clan    => 0,
    	IO::Socket    => 0,
    	Log::Log4perl => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/TacacsPlus/Client.pm', # retrieve abstract from module
       AUTHOR         => 'Jozef Kutej <jozef@kutej.net>') : ()),
	(MM->can('signature_target') ? (SIGN => 1) : ()),
);

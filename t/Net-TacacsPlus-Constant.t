#!/usr/bin/perl

use strict;
use warnings;

use Test::More; # 'no_plan';
BEGIN { plan tests => 1 };

{
	package
		t::constants;

	# Import constants into this clean package
	use Net::TacacsPlus::Constants;

	# Check all package symbols for typos
	main::ok(grep { /^TAC_PLUS_/ } keys %t::constants::, 'No constant typos');
}

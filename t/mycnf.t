#!/usr/bin/perl
# NetMgr::Config->mysql_defaults_file — resolve the root MySQL option file,
# preferring the configured/default /etc/net-mgr/root.conf and only falling
# back to the legacy /root/.my.cnf (with a warning) when the new one is absent.
# The legacy-fallback branch needs a readable /root/.my.cnf, so it's covered
# by SKIP guards rather than asserted unconditionally.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use File::Temp qw(tempfile);
use NetMgr::Config;

# 1. A configured path that exists is returned verbatim (no fallback/warning).
my ($fh, $path) = tempfile(UNLINK => 1);
print $fh "[net-mgr]\nuser=x\n"; close $fh;
is(NetMgr::Config->mysql_defaults_file({ mysql => { defaults => $path } }),
   $path, 'existing configured path returned as-is');

# 2. Missing configured path, no readable legacy -> the configured path comes
#    back (so the eventual "not readable" error names what was asked for).
SKIP: {
    skip "only valid when neither canonical nor legacy is readable here", 1
        if -r '/root/.my.cnf' || -r '/etc/net-mgr/root.conf';
    my $missing = "$path.nope";
    is(NetMgr::Config->mysql_defaults_file({ mysql => { defaults => $missing } }),
       $missing, 'missing configured path, no canonical/legacy -> configured path');
}

# 3. With no cfg, the built-in default is /etc/net-mgr/root.conf.
SKIP: {
    skip "default or legacy happens to be readable here", 1
        if -r '/etc/net-mgr/root.conf' || -r '/root/.my.cnf';
    is(NetMgr::Config->mysql_defaults_file(undef), '/etc/net-mgr/root.conf',
       'undef cfg yields the canonical default path');
}

done_testing;

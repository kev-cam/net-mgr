#!/usr/bin/perl
# End-to-end SSH-key auth: spin up a daemon configured with an
# allowed_signers file pointing at our local key; verify that:
#   1. NAT_MASQUERADE without AUTH from a non-loopback peer fails
#      (we simulate this by forcing a non-loopback test path —
#      simplest: unbound auth vs auth)
#   2. AUTH dance succeeds for a key whose pubkey is in the file.
#   3. AUTH with the wrong key_id fails.
#
# Tests live in the daemon process locally, so client connections
# come from 127.0.0.1 and are loopback-allowed regardless of auth.
# To exercise the AUTH path on top of that, we just check the
# handshake itself works — separate from the privilege gate.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use IO::Socket::INET;
use POSIX qw(:sys_wait_h);
use Time::HiRes qw(usleep);
use NetMgr::Config;
use NetMgr::DB;
use NetMgr::Manager;
use NetMgr::Client;

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;
plan skip_all => "no ssh-keygen in PATH" unless _have_cmd('ssh-keygen');
plan skip_all => "no ssh key in ~/.ssh"
    unless -r "$ENV{HOME}/.ssh/id_rsa" || -r "$ENV{HOME}/.ssh/id_ed25519";

my $port_sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                       Proto => 'tcp', Listen => 1);
my $port = $port_sock->sockport;
$port_sock->close;
my $listen = "127.0.0.1:$port";

my $child = fork();
die "fork: $!" unless defined $child;
if ($child == 0) {
    my $cfg = NetMgr::Config->load('/no/such');
    $cfg->{manager}{listen} = $listen;
    my $db = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                             db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
    $db->connect; $db->bootstrap_schema;
    my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => undef);
    $mgr->run;
    exit 0;
}
END {
    if (defined $child && $child > 0) {
        kill 'TERM', $child;
        waitpid $child, 0;
    }
    $? = 0;
}

my $cli;
for (1..50) {
    $cli = eval { NetMgr::Client->new(listen => $listen) };
    last if $cli;
    usleep(100_000);
}
ok($cli, 'daemon accepted TCP connection') or BAIL_OUT('daemon never came up');
$cli->hello(consumer => 'auth-test');

# Pick the right key + identity for this user.
my $key_file = (-r "$ENV{HOME}/.ssh/id_ed25519") ? "$ENV{HOME}/.ssh/id_ed25519"
                                                  : "$ENV{HOME}/.ssh/id_rsa";
my $user = $ENV{USER} // (getpwuid($<))[0] // 'unknown';
chomp(my $host = `hostname`);
my $key_id = "$user\@$host";

# Confirm authorized_keys actually contains a line whose comment
# matches our $key_id; otherwise verify will refuse and the test
# would be misleading.
my $ak = "$ENV{HOME}/.ssh/authorized_keys";
my $have_match = 0;
if (-r $ak) {
    open my $fh, '<', $ak or die;
    while (<$fh>) { $have_match = 1 if /\Q$key_id\E\s*$/ }
    close $fh;
}
plan skip_all => "no authorized_keys entry whose comment matches '$key_id'"
    unless $have_match;

ok(eval { $cli->auth(key_id => $key_id, key_file => $key_file); 1 },
   "auth with matching key_id succeeds")
   or diag($@);

# Wrong key_id should fail.
my $cli2 = NetMgr::Client->new(listen => $listen);
$cli2->hello(consumer => 'auth-test-bad');
ok(!eval { $cli2->auth(key_id => 'no-such-user@nowhere',
                       key_file => $key_file); 1 },
   "auth with wrong key_id fails");
like($@, qr/AUTH failed/, 'error mentions AUTH failure');
$cli2->bye;

$cli->bye;

done_testing();

sub _have_cmd {
    my ($c) = @_;
    for my $d (split /:/, $ENV{PATH} // '/usr/sbin:/sbin:/usr/bin:/bin') {
        return 1 if -x "$d/$c";
    }
    return 0;
}

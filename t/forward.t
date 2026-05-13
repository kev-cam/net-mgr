#!/usr/bin/perl
# End-to-end test for the FORWARD/UNFORWARD verbs over TCP, using the
# socat backend (forced via [forward] method = socat) so the test
# doesn't need root or iptables. Verifies:
#   - FORWARD installs a working proxy
#   - UNFORWARD takes it down
#   - disconnect tears down any forwards left behind
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
plan skip_all => "no socat in PATH" unless _have_cmd('socat');

# Stand up a tiny TCP echo server we can forward to.
my $echo_sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                       Proto => 'tcp', Listen => 1)
    or die "echo bind: $!";
my $echo_port = $echo_sock->sockport;
my $echo_pid = fork();
die "fork echo: $!" unless defined $echo_pid;
if ($echo_pid == 0) {
    while (my $c = $echo_sock->accept) {
        while (my $line = <$c>) { print {$c} $line }
        close $c;
    }
    exit 0;
}
$echo_sock->close;

# Pick a free port for the daemon, and another for the forward slot.
my $daemon_port = _free_port();
my $slot_port   = _free_port();
my $listen      = "127.0.0.1:$daemon_port";
diag("daemon=$listen slot=$slot_port echo=127.0.0.1:$echo_port");

my $child = fork();
die "fork daemon: $!" unless defined $child;
if ($child == 0) {
    my $cfg = NetMgr::Config->load('/no/such');
    $cfg->{manager}{listen}  = $listen;
    $cfg->{forward}{method}  = 'socat';
    my $db = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                             db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
    $db->connect; $db->bootstrap_schema;
    my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => undef);
    $mgr->run;
    exit 0;
}

END {
    for my $p (grep { defined && $_ > 0 } $child, $echo_pid) {
        kill 'TERM', $p;
        waitpid($p, 0);
    }
    # Don't leak the last child's wstat as our exit status — Test::More
    # has already decided pass/fail.
    $? = 0;
}

# Wait for daemon to bind.
my $cli;
for (1..50) {
    $cli = eval { NetMgr::Client->new(listen => $listen) };
    last if $cli;
    usleep(100_000);
}
ok($cli, 'daemon accepted TCP connection') or BAIL_OUT("daemon never came up");
$cli->hello(consumer => 'forward-test');

# FORWARD slot=$slot_port → echo_port. Should install a socat that
# listens on 127.0.0.1:$slot_port and proxies to the echo server.
my $r = eval { $cli->forward(slot => $slot_port, target => "127.0.0.1:$echo_port") };
ok(!$@, "FORWARD reply OK") or diag($@);
is($r->{slot}, $slot_port, 'slot echoed back');
is($r->{method}, 'socat', 'socat backend in use');

# Wait for the socat to be listening, then round-trip a line.
my $proxy;
for (1..30) {
    $proxy = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                    PeerPort => $slot_port,
                                    Proto => 'tcp', Timeout => 1);
    last if $proxy;
    usleep(50_000);
}
ok($proxy, "connected to forwarded slot $slot_port") or BAIL_OUT("proxy never opened");
print {$proxy} "ping forward\n";
my $line = <$proxy>;
chomp $line if defined $line;
is($line, 'ping forward', 'echo round-trip via forward succeeded');
close $proxy;

# UNFORWARD — proxy port should refuse new connections.
ok(eval { $cli->unforward(slot => $slot_port); 1 }, "UNFORWARD slot=$slot_port") or diag($@);
my $gone;
for (1..20) {
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                   PeerPort => $slot_port,
                                   Proto => 'tcp', Timeout => 1);
    if (!$s) { $gone = 1; last }
    close $s;
    usleep(50_000);
}
ok($gone, 'proxy port refuses connections after UNFORWARD');

# Re-install, then drop the connection — daemon should GC the forward.
my $slot2 = _free_port();
$cli->forward(slot => $slot2, target => "127.0.0.1:$echo_port");
my $ok = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $slot2,
                                Proto => 'tcp', Timeout => 1);
ok($ok, "second forward up on $slot2"); close $ok if $ok;

# Drop the client without UNFORWARD.
$cli->bye;
undef $cli;

my $gone2;
for (1..20) {
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $slot2,
                                   Proto => 'tcp', Timeout => 1);
    if (!$s) { $gone2 = 1; last }
    close $s;
    usleep(100_000);
}
ok($gone2, 'forward auto-removed after disconnect');

done_testing();

sub _free_port {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                   Proto => 'tcp', Listen => 1) or die "bind: $!";
    my $p = $s->sockport;
    $s->close;
    return $p;
}

sub _have_cmd {
    my ($c) = @_;
    for my $d (split /:/, $ENV{PATH} // '/usr/sbin:/sbin:/usr/bin:/bin') {
        return 1 if -x "$d/$c";
    }
    return 0;
}

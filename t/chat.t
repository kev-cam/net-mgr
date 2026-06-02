#!/usr/bin/perl
# Tests net-chat: CHAT_* control verbs, OBSERVE kind=chat_msg, the
# per-session access modes (open/list/request), membership approval,
# presence, and emit-on-change to a session subscriber.
# Run as root (needs a writable netmgr DB via .my.cnf).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::Config;
use NetMgr::DB;
use NetMgr::Manager;
use NetMgr::Protocol qw(parse_line);

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

my $cfg = NetMgr::Config->load('/no/such');
my $db  = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                          db => 'netmgr',
                          schema_dir => "$FindBin::Bin/../sql");
$db->connect; $db->bootstrap_schema;

my $PFX = 'tchat_';

sub cleanup {
    my $dbh = $db->dbh;
    # FK ON DELETE CASCADE means removing the session clears members,
    # messages and presence; presence may also linger from a prior run.
    $dbh->do("DELETE FROM chat_presence WHERE session LIKE ?", undef, "$PFX%");
    $dbh->do("DELETE FROM chat_sessions WHERE name    LIKE ?", undef, "$PFX%");
}
cleanup();

my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => undef);

# Fake clients. A real (here /dev/null) filehandle gives each a unique
# fileno so presence conn_ids work; auth=>verified gives a stable chat
# identity without needing a loopback socket.
sub mkclient {
    my ($ident, $key) = @_;
    open(my $fh, '<', '/dev/null') or die "open /dev/null: $!";
    return {
        sock => $fh, ident => $ident, peer => 'unit', buffer => '',
        kind => 'producer', subs => {},
        ($key ? (auth => { key_id => $key, verified => 1 }) : (auth => undef)),
    };
}

my $owner    = mkclient('owner',  'owner@unit');
my $member   = mkclient('member', 'member@unit');
my $consumer = mkclient('cons',   'cons@unit');
for my $c ($owner, $member, $consumer) {
    $mgr->{clients}{ fileno($c->{sock}) } = $c;
}

my %sent;   # ident => [lines]
{ no warnings 'redefine';
  *NetMgr::Manager::_send = sub {
      my ($self, $cli, $line) = @_;
      push @{ $sent{$cli->{ident}} }, $line;
  };
}

sub feed {
    my ($cli, $line) = @_;
    $sent{$cli->{ident}} = [];
    $mgr->_handle_line($cli, $line);
}
sub lines { @{ $sent{ $_[0]->{ident} } || [] } }
sub last_reply { (grep { /^(OK|ERR|READY)\b/ } lines($_[0]))[-1] // '' }

# --- CHAT_OPEN (open mode) --------------------------------------------
{
    feed($owner, "CHAT_OPEN name=${PFX}open mode=open topic=\"hello there\"");
    like(last_reply($owner), qr/^OK\b.*mode=open/, 'CHAT_OPEN ok');
    my $s = $db->get_chat_session("${PFX}open");
    ok($s, 'session row created');
    is($s->{created_by}, 'owner@unit', 'created_by is the verified key');
    my $m = $db->get_chat_member("${PFX}open", 'owner@unit');
    is($m->{role}, 'owner', 'creator is owner-member');
}

# --- duplicate open rejected ------------------------------------------
{
    feed($owner, "CHAT_OPEN name=${PFX}open");
    like(last_reply($owner), qr/^ERR.*exists/, 'duplicate session rejected');
}

# --- post + emit to a session subscriber ------------------------------
{
    feed($consumer, "SUBSCRIBE sub=1 mode=snapshot+stream FROM chat_messages"
                  . " WHERE session = '${PFX}open'");
    ok((grep { /^EOS sub=1/ } lines($consumer)), 'snapshot EOS');

    feed($owner, "OBSERVE kind=chat_msg session=${PFX}open body=\"first post\"");
    like(last_reply($owner), qr/^OK/, 'post accepted');
    my @rows = grep { /^ROW sub=1 .*table=chat_messages/ } lines($consumer);
    ok(scalar @rows >= 1, 'message streamed to subscriber');
    ok((grep { /body="?first post"?/ } @rows), 'streamed row carries body');
    ok((grep { /sender=owner\@unit/   } @rows), 'sender server-stamped');
}

# --- post to a missing session ----------------------------------------
{
    feed($owner, "OBSERVE kind=chat_msg session=${PFX}nope body=hi");
    like(last_reply($owner), qr/^ERR.*no such session/, 'missing session rejected');
}

# --- request mode: join -> requested -> approve -> post ---------------
{
    feed($owner, "CHAT_OPEN name=${PFX}req mode=request");
    like(last_reply($owner), qr/^OK/, 'request-mode session opened');

    feed($member, "OBSERVE kind=chat_msg session=${PFX}req body=early");
    like(last_reply($member), qr/^ERR.*not a member/, 'non-member cannot post');

    feed($member, "CHAT_JOIN session=${PFX}req");
    like(last_reply($member), qr/^OK.*state=requested/, 'join becomes a request');
    my $m = $db->get_chat_member("${PFX}req", 'member@unit');
    is($m->{state}, 'requested', 'member row is requested');

    feed($owner, "CHAT_APPROVE session=${PFX}req principal=member\@unit");
    like(last_reply($owner), qr/^OK.*state=member/, 'owner approves');
    is($db->get_chat_member("${PFX}req", 'member@unit')->{state}, 'member',
       'member promoted');

    feed($member, "OBSERVE kind=chat_msg session=${PFX}req body=later");
    like(last_reply($member), qr/^OK/, 'approved member can post');
}

# --- list mode: blocked until allowed ---------------------------------
{
    feed($owner, "CHAT_OPEN name=${PFX}list mode=list");
    feed($member, "CHAT_JOIN session=${PFX}list");
    like(last_reply($member), qr/^ERR.*allow-list/, 'list join blocked');

    feed($owner, "CHAT_ALLOW session=${PFX}list principal=member\@unit");
    like(last_reply($owner), qr/^OK/, 'owner allows member');
    feed($member, "CHAT_JOIN session=${PFX}list");
    like(last_reply($member), qr/^OK.*state=member/, 'allowed member joins');
}

# --- presence join/leave ----------------------------------------------
{
    feed($owner, "CHAT_JOIN session=${PFX}open");
    like(last_reply($owner), qr/^OK/, 'owner joins open session');
    my $rows = $db->dbh->selectall_arrayref(
        "SELECT principal FROM chat_presence WHERE session = ?",
        { Slice => {} }, "${PFX}open");
    ok((grep { $_->{principal} eq 'owner@unit' } @$rows), 'presence row present');

    feed($owner, "CHAT_LEAVE session=${PFX}open");
    my ($n) = $db->dbh->selectrow_array(
        "SELECT COUNT(*) FROM chat_presence WHERE session = ? AND principal = ?",
        undef, "${PFX}open", 'owner@unit');
    is($n, 0, 'presence cleared on leave');
}

# --- close: read-only afterwards --------------------------------------
{
    feed($owner, "CHAT_CLOSE name=${PFX}open");
    like(last_reply($owner), qr/^OK.*status=closed/, 'session closed');
    feed($owner, "OBSERVE kind=chat_msg session=${PFX}open body=after");
    like(last_reply($owner), qr/^ERR.*closed/, 'no posting to a closed session');
}

# --- unauthorized create ----------------------------------------------
{
    my $anon = mkclient('anon', undef);   # no auth, not loopback
    $mgr->{clients}{ fileno($anon->{sock}) } = $anon;
    feed($anon, "CHAT_OPEN name=${PFX}anon");
    like(last_reply($anon), qr/^ERR.*not authorized/, 'anonymous create rejected');
}

cleanup();
done_testing();

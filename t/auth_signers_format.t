#!/usr/bin/perl
# NetMgr::Auth accepts both formats in a signers file (allowed_signers /
# allowed_chat): native allowed_signers lines AND raw authorized_keys/pubkey
# lines (so `cat id_rsa.pub >> /etc/net-mgr/allowed_chat` just works).
# No DB needed — exercises sign + NetMgr::Auth::verify directly.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use File::Temp;
use MIME::Base64 qw(encode_base64);
use NetMgr::Auth;

plan skip_all => "no ssh-keygen in PATH" unless _have('ssh-keygen');
my ($key, $pub);
for my $k (qw(id_ed25519 id_rsa)) {
    if (-r "$ENV{HOME}/.ssh/$k" && -r "$ENV{HOME}/.ssh/$k.pub") {
        $key = "$ENV{HOME}/.ssh/$k"; $pub = "$ENV{HOME}/.ssh/$k.pub"; last;
    }
}
plan skip_all => "no readable ssh key+pub in ~/.ssh" unless $key;

# The principal a raw pubkey converts to is its comment field.
open my $pf, '<', $pub or die;
chomp(my $publine = <$pf>); close $pf;
my @p = split /\s+/, $publine;
my $key_id = $p[2] // 'key-' . substr($p[1], 0, 12);   # comment, else key-<...>

# helper: sign a nonce with our key the way NetMgr::Client->auth does
sub sign_nonce {
    my ($nonce) = @_;
    my $tn = File::Temp->new; print $tn $nonce; $tn->flush;
    my $ts = File::Temp->new(SUFFIX => '.sig');
    my $rc = system("ssh-keygen -q -Y sign -n net-mgr -f " . $key
                  . " < " . $tn->filename . " > " . $ts->filename . " 2>/dev/null");
    die "sign rc=" . ($rc>>8) if $rc;
    open my $sf, '<', $ts->filename or die; local $/; my $sig = <$sf>; close $sf;
    return encode_base64($sig, '');
}

# verify a key_id against a signers file with given content
sub verify_against {
    my ($content, $kid) = @_;
    my $f = File::Temp->new; print $f $content; $f->flush;
    my $state = NetMgr::Auth::new_state(signers_path => $f->filename,
                                        authorized_keys => undef);
    my $nonce = NetMgr::Auth::fresh_nonce();
    my $sig = sign_nonce($nonce);
    my ($ok, $err) = NetMgr::Auth::verify($state, $kid, $nonce, $sig);
    return ($ok, $err, $f);   # keep $f alive for the verify
}

# 1. RAW pubkey line (the `cat id_rsa.pub` case) — must now verify.
{
    my ($ok, $err) = verify_against("$publine\n", $key_id);
    ok($ok, "raw pubkey line in signers file verifies (principal=$key_id)")
        or diag("err: $err");
}

# 2. Native allowed_signers line — must still verify.
{
    my $native = qq($key_id namespaces="net-mgr" $p[0] $p[1]\n);
    my ($ok, $err) = verify_against($native, $key_id);
    ok($ok, "native allowed_signers line still verifies") or diag("err: $err");
}

# 3. Wrong principal still fails (no accidental wildcard).
{
    my ($ok) = verify_against("$publine\n", 'someone-else@nowhere');
    ok(!$ok, "mismatched principal is rejected");
}

done_testing();

sub _have { my ($c)=@_; for (split /:/, $ENV{PATH}//'') { return 1 if -x "$_/$c" } 0 }

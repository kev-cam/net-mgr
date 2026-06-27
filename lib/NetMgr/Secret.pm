package NetMgr::Secret;
# Minimal per-name secret store: read /etc/net-mgr/secrets/<name>, strip the
# trailing newline, return the content. Files must be root-owned mode 600 —
# we warn loudly otherwise (but still hand the secret back, because refusing
# would make the warning easy to ignore). Never logged: the secret itself never
# appears in the daemon's log, only its NAME does, so a leaked log doesn't leak
# the credential.
#
# Usage:
#   my $s = NetMgr::Secret::get('he_net');           # reads .../secrets/he_net
#   my ($u, $p) = NetMgr::Secret::get_userpass('he_net');  # parses "user:pass"
#
# The HE update key (per-tunnel, NOT your tunnelbroker login password) goes in
# the file as a single line `username:update_key`. Get the key from
# tunnelbroker.net -> your tunnel -> Advanced tab.

use strict;
use warnings;
use Exporter 'import';

our @EXPORT_OK = qw(get get_userpass dir);

sub dir { '/etc/net-mgr/secrets' }

sub _path {
    my ($name) = @_;
    return undef unless defined $name && $name =~ m{\A[A-Za-z0-9._-]+\z};
    return dir() . "/$name";
}

my %_warned;
sub get {
    my ($name) = @_;
    my $p = _path($name) or return (undef, "bad secret name '$name'");
    return (undef, "secret '$name' not readable at $p") unless -r $p;
    my @st = stat $p;
    if (@st && !$_warned{$p}++) {
        my $mode = $st[2] & 07777;
        if ($mode & 077) {
            warn sprintf("net-mgr: WARNING secret '$p' is mode %04o — should be 0600 (chmod 600 %s)\n",
                         $mode, $p);
        }
    }
    open my $fh, '<', $p or return (undef, "open $p: $!");
    local $/; my $v = <$fh>; close $fh;
    $v //= ''; $v =~ s/\s+\z//;          # trailing whitespace only — body kept verbatim
    return (length $v ? $v : undef, length $v ? undef : "secret '$name' is empty");
}

# Parse a `user:password` (one line) secret. Returns ($user, $pass, $err).
sub get_userpass {
    my ($name) = @_;
    my ($v, $err) = get($name);
    return (undef, undef, $err) if defined $err;
    my ($u, $p) = split /:/, $v, 2;
    return (undef, undef, "secret '$name' is not 'user:password'")
        unless defined $u && length $u && defined $p && length $p;
    return ($u, $p, undef);
}

1;

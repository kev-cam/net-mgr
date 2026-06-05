package NetMgr::Auth;
# SSH-key authentication for net-mgr.
#
# The daemon authenticates clients with the SSHSIG scheme that
# OpenSSH 8.2+ ships in `ssh-keygen -Y sign` / `-Y verify`. No
# actual SSH login happens; we just borrow the signature primitive.
#
# Workflow over the wire:
#
#   client → AUTH key-id=ID
#   server → CHALLENGE nonce=base64
#   client → (signs nonce with its private key, namespace=net-mgr)
#   client → AUTH_RESPONSE sig=base64(armored sshsig)
#   server → OK   on success / ERR on failure
#
# After OK the connection is marked {auth}{key_id}=ID and any verb
# that requires authentication will accept it regardless of source IP.
#
# Trust roots:
#   /etc/net-mgr/allowed_signers   — primary, OpenSSH allowed_signers
#                                    format with namespaces="net-mgr"
#   /root/.ssh/authorized_keys     — fallback; lines are converted on
#                                    the fly to allowed_signers form
#                                    using their comment (or the key
#                                    fingerprint if no comment) as
#                                    the principal.
#
# Both are merged into a per-process tempfile so a single
# `ssh-keygen -Y verify` call can match against either source.
# The tempfile is rebuilt on first use and on demand (SIGHUP, etc.).

use strict;
use warnings;
use File::Temp ();
use MIME::Base64 ();

use constant NAMESPACE => 'net-mgr';

# ---- random nonce ---------------------------------------------------

# 32 bytes of /dev/urandom, base64 encoded (no newlines).
sub fresh_nonce {
    open my $fh, '<', '/dev/urandom' or die "open /dev/urandom: $!";
    binmode $fh;
    my $buf;
    read($fh, $buf, 32) == 32 or die "short read from /dev/urandom";
    close $fh;
    return MIME::Base64::encode_base64($buf, '');
}

# ---- allowed-signers tempfile management ---------------------------

# Returns a hashref with state shared across calls. Caller (Manager)
# stashes one of these on $self.
sub new_state {
    my (%args) = @_;
    return {
        signers_path     => $args{signers_path}    // '/etc/net-mgr/allowed_signers',
        authorized_keys  => $args{authorized_keys} // _default_authorized_keys(),
        tempfile         => undef,    # File::Temp object once built
        last_built       => 0,
        rebuild_interval => $args{rebuild_interval} // 60,
    };
}

sub _default_authorized_keys {
    # Use the daemon's effective-uid HOME if we can; fall back to root.
    if ($> == 0) { return '/root/.ssh/authorized_keys' }
    my $home = (getpwuid($>))[7];
    return defined $home ? "$home/.ssh/authorized_keys" : undef;
}

# (Re)build the merged tempfile. Returns the tempfile path. Cached
# for $rebuild_interval seconds; force rebuild with $force=1.
sub merged_signers_path {
    my ($state, $force) = @_;
    my $now = time();
    if (!$force
     && $state->{tempfile}
     && ($now - $state->{last_built}) < $state->{rebuild_interval}) {
        return $state->{tempfile}->filename;
    }
    # Defensive: a caller may have done `local $/` (slurp mode) and
    # not restored it before calling us. Pin $/ for the line-oriented
    # reads below.
    local $/ = "\n";
    my $tmp = File::Temp->new(TEMPLATE => 'netmgr-signers-XXXXXX',
                              TMPDIR => 1, UNLINK => 1, SUFFIX => '.txt');
    binmode $tmp;
    my $count = 0;

    if ($state->{signers_path} && -r $state->{signers_path}) {
        open my $fh, '<', $state->{signers_path}
            or warn "auth: open $state->{signers_path}: $!\n";
        while ($fh && (my $line = <$fh>)) {
            chomp $line;
            next if $line =~ /^\s*(?:#|$)/;
            # Accept raw pubkey / authorized_keys lines (key-type first, no
            # principal) as well as native allowed_signers lines, so a plain
            # `cat id_rsa.pub >> allowed_chat` works without hand-formatting.
            # Native lines (principal first) pass through unchanged; the
            # converted principal comes from the pubkey comment, which is the
            # key_id ($USER@$(hostname)) the client AUTHs as.
            if ($line =~ /^\s*(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s/) {
                my $converted = _authorized_to_allowed($line);
                next unless defined $converted;
                $line = $converted;
            }
            print $tmp "$line\n";
            $count++;
        }
        close $fh if $fh;
    }

    if ($state->{authorized_keys} && -r $state->{authorized_keys}) {
        open my $fh, '<', $state->{authorized_keys}
            or warn "auth: open $state->{authorized_keys}: $!\n";
        while ($fh && (my $line = <$fh>)) {
            chomp $line;
            next if $line =~ /^\s*(?:#|$)/;
            my $converted = _authorized_to_allowed($line);
            next unless defined $converted;
            print $tmp "$converted\n";
            $count++;
        }
        close $fh if $fh;
    }

    $tmp->flush;
    $state->{tempfile}   = $tmp;
    $state->{last_built} = $now;
    $state->{count}      = $count;
    return $tmp->filename;
}

# authorized_keys line:    [options] KEYTYPE BASE64KEY [comment...]
# allowed_signers line:    PRINCIPAL [options] KEYTYPE BASE64KEY
# We use the comment (preferred) or a fingerprint synthesised from
# the first 12 chars of the base64 key as the principal.
sub _authorized_to_allowed {
    my ($line) = @_;
    return undef unless defined $line;
    # strip leading options if present (token doesn't start with ssh-/sk-/ecdsa-)
    my @parts = split /\s+/, $line, 2;
    return undef unless @parts == 2;
    if ($parts[0] !~ /^(ssh-|ecdsa-|sk-)/) {
        # leading options group; advance to keytype
        ($parts[1] =~ /^(ssh-|ecdsa-|sk-)/) or return undef;
    } else {
        # already starts with keytype; refold
        @parts = ($parts[0], $parts[1]);
    }
    my ($keytype, $rest);
    if ($line =~ /\b((?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+))\s+(\S+)\s*(.*)$/) {
        my ($kt, $kdata, $comment) = ($1, $2, $3);
        $comment //= '';
        $comment =~ s/^\s+|\s+$//g;
        my $principal = length($comment) ? $comment
                                         : 'key-' . substr($kdata, 0, 12);
        # OpenSSH allowed_signers needs the principal as a single token.
        # If the comment has spaces, replace them with underscores.
        $principal =~ s/\s+/_/g;
        my $ns = NAMESPACE;
        return qq($principal namespaces="$ns" $kt $kdata);
    }
    return undef;
}

# ---- verify ---------------------------------------------------------

# Returns (1, undef) on success, (0, $error_message) on failure.
# $sig_b64 is the base64-encoded armored sshsig as the client sent it.
sub verify {
    my ($state, $key_id, $nonce_b64, $sig_b64) = @_;
    return (0, 'missing key-id') unless defined $key_id  && length $key_id;
    return (0, 'missing nonce')  unless defined $nonce_b64 && length $nonce_b64;
    return (0, 'missing sig')    unless defined $sig_b64 && length $sig_b64;

    my $signers = merged_signers_path($state);

    my $nonce_file = File::Temp->new(TEMPLATE => 'netmgr-nonce-XXXXXX',
                                     TMPDIR => 1, UNLINK => 1);
    binmode $nonce_file;
    print $nonce_file $nonce_b64;
    $nonce_file->flush;

    my $sig_file = File::Temp->new(TEMPLATE => 'netmgr-sig-XXXXXX',
                                   TMPDIR => 1, UNLINK => 1, SUFFIX => '.sig');
    binmode $sig_file;
    print $sig_file MIME::Base64::decode_base64($sig_b64);
    $sig_file->flush;

    my $ns = NAMESPACE;
    my @cmd = ('ssh-keygen', '-Y', 'verify',
               '-n', $ns,
               '-I', $key_id,
               '-f', $signers,
               '-s', $sig_file->filename);
    # Feed nonce on stdin; capture stderr for diagnostics.
    my $pid = open my $fh, '-|';
    if (!defined $pid) { return (0, "fork: $!") }
    if ($pid == 0) {
        open STDIN, '<', $nonce_file->filename
            or do { print "open nonce: $!"; exit 127 };
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 127;
    }
    local $/;
    my $out = <$fh> // '';
    close $fh;
    my $rc = $? >> 8;
    chomp $out;
    return (1, undef) if $rc == 0;
    $out =~ s/\s+/ /g;
    return (0, "ssh-keygen rc=$rc: $out");
}

1;

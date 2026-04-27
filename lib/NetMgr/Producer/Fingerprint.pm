package NetMgr::Producer::Fingerprint;
# SSH-fingerprint a remote host to identify what it is:
#   dd-wrt          — DD-WRT router/AP (`nvram get DD_BOARD` returns a board)
#   openwrt         — OpenWRT router (/etc/openwrt_release exists)
#   linux           — generic Linux box (uname returns Linux)
#   linux-dnsmasq   — Linux + dnsmasq present (interesting for future
#                     dhcp-pusher integration)
#   ssh-deny        — connected but no auth (password-only / key missing)
#   unreachable     — couldn't open the SSH connection
#   unknown         — connected but classifier didn't fire
#
# probe_host(ip => …, ssh_user => 'root', ssh_timeout => 3) → hashref:
#   { ip, kind, name, board, openwrt, dnsmasq, uname, notes }

use strict;
use warnings;
use Carp qw(croak);

# Single-shot SSH command. Sentinel sections so the parse is robust.
my $REMOTE_PROBE = <<'SH';
echo ===NVRAM===
nvram get DD_BOARD 2>/dev/null
nvram get router_name 2>/dev/null
echo ===OPENWRT===
[ -f /etc/openwrt_release ] && cat /etc/openwrt_release 2>/dev/null
echo ===UNAME===
uname -srm 2>/dev/null
echo ===DNSMASQ===
command -v dnsmasq 2>/dev/null
echo ===END===
SH

sub probe_host {
    my (%args) = @_;
    my $ip = $args{ip} or croak "ip required";
    my $ssh_user    = $args{ssh_user}    // 'root';
    my $ssh_timeout = $args{ssh_timeout} // 3;

    my $result = {
        ip => $ip, kind => 'unknown',
        name => undef, board => undef, openwrt => undef,
        dnsmasq => undef, uname => undef, notes => '',
    };

    my @cmd = (
        'ssh',
        '-o', 'BatchMode=yes',
        '-o', "ConnectTimeout=$ssh_timeout",
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-n',
        "$ssh_user\@$ip",
        $REMOTE_PROBE,
    );

    my $pid = open(my $fh, '-|');
    return _err($result, 'fork failed') unless defined $pid;
    if ($pid == 0) {
        # capture stderr too; classify denied/timeout from text
        open STDERR, '>&', \*STDOUT;
        exec @cmd;
        exit 127;
    }
    my @lines = <$fh>;
    close $fh;
    my $exit = $? >> 8;

    if (!@lines) {
        $result->{kind}  = 'unreachable';
        $result->{notes} = "ssh exited $exit, no output";
        return $result;
    }

    my $blob = join '', @lines;
    if ($blob =~ /Permission denied/i) {
        $result->{kind}  = 'ssh-deny';
        $result->{notes} = 'permission denied (no key/auth)';
        return $result;
    }
    if ($blob =~ /Connection (?:refused|timed out|closed)|No route to host|Could not resolve/i) {
        $result->{kind}  = 'unreachable';
        $result->{notes} = 'no ssh';
        return $result;
    }

    # Walk the sectioned output
    my $section;
    my @nvram;
    my @openwrt;
    my $uname;
    my $dnsmasq;
    for my $line (@lines) {
        chomp $line;
        next if $line eq '';
        if ($line =~ /^===(\w+)===$/) { $section = $1; next }
        next unless $section;
        if    ($section eq 'NVRAM')   { push @nvram, $line }
        elsif ($section eq 'OPENWRT') { push @openwrt, $line }
        elsif ($section eq 'UNAME')   { $uname   = $line }
        elsif ($section eq 'DNSMASQ') { $dnsmasq = $line }
    }

    if (@nvram) {
        # Order: DD_BOARD then router_name
        $result->{board} = $nvram[0] if defined $nvram[0] && length $nvram[0];
        $result->{name}  = $nvram[1] if defined $nvram[1] && length $nvram[1];
        $result->{kind}  = 'dd-wrt' if $result->{board};
    }
    if (@openwrt) {
        $result->{openwrt} = join "\n", @openwrt;
        $result->{kind}    = 'openwrt' if $result->{kind} eq 'unknown';
    }
    if (defined $uname && length $uname) {
        $result->{uname} = $uname;
        $result->{kind}  = 'linux' if $result->{kind} eq 'unknown' && $uname =~ /^Linux/;
    }
    if (defined $dnsmasq && length $dnsmasq) {
        $result->{dnsmasq} = $dnsmasq;
        $result->{kind}    = 'linux-dnsmasq' if $result->{kind} eq 'linux';
    }
    return $result;
}

sub _err {
    my ($r, $msg) = @_;
    $r->{kind}  = 'error';
    $r->{notes} = $msg;
    return $r;
}

# ---- cache (TSV) -----------------------------------------------------
# Format: ip\tlast_probed_epoch\tkind\tname\tboard\tnotes
# One record per IP (latest wins on collisions).

use Fcntl qw(:flock);

sub load_cache {
    my ($path) = @_;
    my %c;
    return \%c unless $path && -f $path;
    open my $fh, '<', $path or return \%c;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*(?:#|$)/;
        my @f = split /\t/, $line, 6;
        next unless $f[0] && $f[1];
        $c{ $f[0] } = {
            ip          => $f[0],
            last_probed => $f[1] + 0,
            kind        => $f[2] // '',
            name        => $f[3] // '',
            board       => $f[4] // '',
            notes       => $f[5] // '',
        };
    }
    close $fh;
    return \%c;
}

sub save_cache {
    my ($path, $cache) = @_;
    return unless $path;
    require File::Basename;
    my $dir = File::Basename::dirname($path);
    -d $dir or eval { require File::Path; File::Path::make_path($dir) };
    open my $fh, '>', "$path.tmp" or croak "open $path.tmp: $!";
    flock $fh, LOCK_EX;
    for my $ip (sort keys %$cache) {
        my $r = $cache->{$ip};
        print {$fh} join("\t",
            $r->{ip}, $r->{last_probed}, $r->{kind},
            $r->{name} // '', $r->{board} // '',
            ($r->{notes} // '') =~ tr/\t\n/ /r ),
            "\n";
    }
    flock $fh, LOCK_UN;
    close $fh;
    rename "$path.tmp", $path or croak "rename $path: $!";
}

sub is_fresh {
    my ($entry, $ttl_seconds) = @_;
    return 0 unless $entry && $entry->{last_probed};
    return (time() - $entry->{last_probed}) < $ttl_seconds;
}

1;

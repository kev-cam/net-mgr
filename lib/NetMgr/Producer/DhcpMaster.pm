package NetMgr::Producer::DhcpMaster;
# Parses an ISC dhcpd-style config file (e.g. /etc/net-mgr/dhcp.master,
# /etc/net-mgr/dhcp.extra). Extracts:
#   - host blocks   → { type=>'host',   name, mac, ip, file }
#   - subnet blocks → { type=>'subnet', net, mask, ranges => [[lo,hi],...] }
#
# Recursively follows `include "PATH";` directives. The user's
# dhcp.master uses one-line host blocks like:
#   host deadend { hardware ethernet 12:34:..; fixed-address 192.168.223.200;
#   }
# but multi-line blocks work too. Nested braces (group/if/else) are
# tolerated because the host/subnet regexes don't try to span them.

use strict;
use warnings;
use Carp qw(croak);
use File::Basename qw(dirname);
use File::Spec;

# parse_file($path) — returns a list of records.
sub parse_file {
    my ($path) = @_;
    my @out;
    _parse_into($path, \@out, {});
    return @out;
}

sub _parse_into {
    my ($path, $out, $seen) = @_;
    my $abs = File::Spec->rel2abs($path);
    croak "include loop on $abs" if $seen->{$abs}++;
    open my $fh, '<', $path or croak "open $path: $!";
    my $text = do { local $/; <$fh> };
    close $fh;

    # Process and remove `include "..."` directives first.
    my $dir = dirname($path);
    while ($text =~ s/\binclude\s+"([^"]+)"\s*;//) {
        my $inc = $1;
        $inc = File::Spec->rel2abs($inc, $dir) unless File::Spec->file_name_is_absolute($inc);
        if (-f $inc) {
            _parse_into($inc, $out, $seen);
        } else {
            warn "dhcp include '$inc' not found (referenced from $path)\n";
        }
    }

    # Strip line comments. Done after include processing in case any
    # `# include "..."` got commented out (treat as commented = not included).
    $text =~ s/#[^\n]*//g;

    # host NAME { ... }
    while ($text =~ /\bhost\s+(\S+)\s*\{([^{}]*?)\}/gs) {
        my ($name, $body) = ($1, $2);
        my $mac = ($body =~ /hardware\s+ethernet\s+([0-9a-fA-F:]{17})/) ? lc $1 : undef;
        my $ip  = ($body =~ /fixed-address\s+(\d+\.\d+\.\d+\.\d+)/)     ? $1 : undef;
        next unless $mac && $ip;
        push @$out, {
            type => 'host',
            name => $name,
            mac  => $mac,
            ip   => $ip,
            file => $path,
        };
    }

    # subnet NET netmask MASK { ... range A B; ... }
    # Also captures the optional `# zone=NAME` comment that appears after
    # the opening brace, plus inner `option` directives — needed by
    # net-gen-dnsmasq which translates these to dnsmasq tag-options.
    # Run on raw text so the comment-stripped pass above doesn't kill
    # the `# zone=` annotation; we strip whitespace explicitly here.
    my $raw = do { open my $f, '<', $path or croak "open $path: $!"; local $/; <$f> };
    while ($raw =~ /\bsubnet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\d+\.\d+\.\d+\.\d+)\s*\{([^{}]*)\}/gs) {
        my ($net, $mask, $body) = ($1, $2, $3);
        # Take the first `# zone=foo` that appears anywhere in the block.
        my $zone = ($body =~ /#\s*zone\s*=\s*([\w-]+)/) ? $1 : undef;
        # Strip line comments before parsing options/ranges.
        (my $clean = $body) =~ s/#[^\n]*//g;
        my @ranges;
        while ($clean =~ /\brange\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s*;/g) {
            push @ranges, [$1, $2];
        }
        my %options;
        while ($clean =~ /\boption\s+([\w-]+)\s+([^;]+);/g) {
            my ($k, $v) = ($1, $2);
            $v =~ s/^\s+|\s+$//g;
            $v =~ s/^"(.*)"$/$1/;
            $options{$k} = $v;
        }
        push @$out, {
            type    => 'subnet',
            net     => $net,
            mask    => $mask,
            zone    => $zone,
            ranges  => \@ranges,
            options => \%options,
            file    => $path,
        };
    }
}

# hosts_only(@records) — convenience filter
sub hosts_only   { grep { $_->{type} eq 'host'   } @_ }
sub subnets_only { grep { $_->{type} eq 'subnet' } @_ }

1;

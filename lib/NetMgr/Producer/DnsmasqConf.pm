package NetMgr::Producer::DnsmasqConf;
# The single implementation of "what should dnsmasq's reservation and hosts
# data look like".
#
# It lived inside bin/net-gen-dnsmasq, which was fine while files were the only
# consumer. They are not: the patched dnsmasq can now pull the same records over
# the net-mgr protocol, and a second implementation of the naming policy is
# exactly how the file path and the protocol path would silently disagree about
# DNS. There is a lot of policy here to get wrong -- the machine-primary-name
# join, multi-homed qualification, -air kept as the final postfix, zone naming
# and indexing, dedup by MAC for DHCP but by IP for hosts, and two different
# sort orders. One copy, two callers.
#
# render() is PURE: it takes already-fetched rows and returns text. Callers
# differ in how they fetch (net-gen-dnsmasq via NetMgr::Client, the daemon
# straight from its own DB handle) and in what they do with the result (write
# files, or answer a POLL), and neither concern belongs here.
#
#   my $r = NetMgr::Producer::DnsmasqConf::render(
#             reservations => \@resv, machines => \@m,
#             interfaces   => \@if,   ranges   => \@rg,
#             domain => 'grfx.com', lease => 1440,
#             qualify => 0,          # [dnsmasq] multihomed = qualified
#             bare_bank => 1,        # layout=dirs: bank lines, no dhcp-host=
#             zone_overrides => ['192.168.15.0/24=dmz'],
#             warn => sub { ... });
#   $r->{zones}{dmz}{dhcp}    # reservation lines for that zone
#   $r->{zones}{dmz}{hosts}   # hosts lines for that zone

use strict;
use warnings;
use Carp qw(croak);

sub _net24 { my @o = split /\./, ($_[0] // ''); "$o[0].$o[1].$o[2]" }
sub _ipkey { my @o = split /\./, ($_[0] // '0.0.0.0'); (($o[0]*256+$o[1])*256+$o[2])*256+$o[3] }
# dhcp-host name is the short form: strip the side suffix (-up/-down/-dmz/-home),
# keep -air (a distinct wifi interface). Suffixed names stay in the hosts file.
sub _short { my $n = shift // ''; $n =~ s/-(up|down|dmz|home)$//; return $n }

# An adapter marker says WHICH NIC, not which segment, so it stays at the very
# end of a qualified name: u32u's wifi leg on the dmz is u32u-dmz-air, never
# u32u-air-dmz. That keeps -air readable off the tail no matter how many
# zone/index parts the middle grows. -air is the only such marker in this fleet
# (47 names carry it; the next most common tails, -up/-down, are directional).
sub _split_iface {
    my $n = shift // '';
    return ($n, "-$1") if $n =~ s/-(air)$//i;
    return ($n, '');
}
# reverse of the qualified form, for reporting: strip -air, any index, the zone
sub _dequal { my $n = shift // ''; $n =~ s/-air$//; $n =~ s/-\d+$//; $n =~ s/-[a-z0-9]+$//; $n }
sub _rkey { lc($_[0]{mac} // '') . '|' . ($_[0]{ip} // '') }

# Is $own the name of a LEG of the machine recorded as $mach? Same test pass 1
# uses to decide a rename: equal bases, or the machine's base plus a suffix
# (nas3-dwn2 is an nas3 leg; wc13 is not an lg-g4 leg). Identity here hangs off
# the MAC — a machine record is only a grouping of MACs, and this fleet's
# grouping is polluted by hostname collisions, so it may not overrule the name
# the MAC's own reservation carries.
sub _same_host {
    my ($own, $mach) = @_;
    return 0 unless defined $own  && length $own
                 && defined $mach && length $mach;
    my $o = lc(( _split_iface($own)  )[0]);
    my $m = lc(( _split_iface($mach) )[0]);
    return 1 if $o eq $m;
    return 1 if index($o, "$m-") == 0;
    return 0;
}

sub render {
    my (%a) = @_;
    my $resv   = $a{reservations} || [];
    my $M      = $a{machines}     || [];
    my $IF     = $a{interfaces}   || [];
    my $RG     = $a{ranges}       || [];
    my $domain = $a{domain}       // 'grfx.com';
    my $lease  = $a{lease}        // 1440;
    my $dirs   = $a{bare_bank}    ? 1 : 0;
    my @zone_opt = @{ $a{zone_overrides} || [] };
    my $warn   = $a{warn} || sub { CORE::warn(@_) };
    my %zone_src_out;

    # subnet(/24) -> zone, sourced from the DB so this file and NetMgr::Resolver
    # cannot drift: the resolver answers <host>-<zone> out of dhcp_ranges.zone,
    # and until now the names lived only in a literal here.
    #
    # Keyed on subnet_cidr, NOT start_ip/end_ip: a zone names the whole segment,
    # while the ranges are only the DHCP pools. Every static address — nas3 at
    # .223.220/.221 and .15.104 among them — sits outside every pool, so matching
    # on pool bounds would leave exactly the infrastructure hosts unzoned.
    my (%zone_of_24, %zone_src);
    for my $r (@$RG) {
        my $z = $r->{zone};
        next unless defined $z && length $z;
        my $cidr = $r->{subnet_cidr} // next;
        $cidr =~ s{/\d+$}{}; $cidr =~ s/\.0$//;      # 192.168.15.0/24 -> 192.168.15
        # One subnet with two zone names would silently split its hosts across
        # two files. Take the first and say so rather than letting hash order pick.
        if (defined $zone_of_24{$cidr} && lc $zone_of_24{$cidr} ne lc $z) {
            $warn->("net-gen-dnsmasq: $cidr.0/24 is tagged both '$zone_of_24{$cidr}'"
               . " and '$z' in dhcp_ranges; using '$zone_of_24{$cidr}'."
               . " Fix with: net-reserve set-zone $cidr.0/24 <name>\n");
            next;
        }
        $zone_of_24{$cidr} = $z;
        $zone_src{$cidr}   = 'db';
    }
    # Site fallback, kept so a DB that has not been tagged yet still generates the
    # same files it did before rather than silently emitting nothing.
    my %zone_fallback = ('192.168.15' => 'dmz', '192.168.223' => 'home');
    for my $cidr (sort keys %zone_fallback) {
        next if defined $zone_of_24{$cidr};
        $zone_of_24{$cidr} = $zone_fallback{$cidr};
        $zone_src{$cidr}   = 'built-in fallback';
        $warn->("net-gen-dnsmasq: $cidr.0/24 has no zone in dhcp_ranges; using"
           . " built-in '$zone_fallback{$cidr}'. Persist it with:"
           . " net-reserve set-zone $cidr.0/24 $zone_fallback{$cidr}\n");
    }
    for my $z (@zone_opt) {                          # --zone CIDR=name overrides both
        my ($cidr, $name) = split /=/, $z, 2;
        next unless $cidr && defined $name && length $name;
        $cidr =~ s{/\d+$}{}; $cidr =~ s/\.0$//;
        $zone_of_24{$cidr} = $name;
        $zone_src{$cidr}   = '--zone';
    }

    # mac -> suffixed per-side machine name (for the hosts/DNS file)
    my %mname = map { $_->{id} => $_->{primary_name} } grep { $_->{primary_name} } @$M;
    my %mac2host;
    for my $i (@$IF) {
        next unless $i->{mac} && $i->{machine_id};
        my $n = $mname{ $i->{machine_id} } or next;
        $mac2host{ lc $i->{mac} } = $n;
    }

    my (%by_zone, $skipped, %skipped_24);
    for my $r (@$resv) {
        next unless $r->{ip} && $r->{mac};
        my $zone = $zone_of_24{ _net24($r->{ip}) };
        if (!$zone) { $skipped++; $skipped_24{ _net24($r->{ip}) }++; next }
        push @{ $by_zone{$zone} }, $r;
    }
    if ($skipped) {
        $warn->("net-gen-dnsmasq: skipped $skipped reservation(s) on subnets with no"
           . " zone mapping: "
           . join(', ', map { "$_.0/24 ($skipped_24{$_})" } sort keys %skipped_24)
           . "\n  name them with: net-reserve set-zone <cidr> <name>\n");
    }
    # A zone lookup that resolves nothing must not be mistaken for "no hosts".
    # Every reservation is filtered through the zone map, so an untagged DB
    # yields an empty file set. _emit_generated already refuses to write or
    # SIGHUP in that case, so nothing is destroyed — but it only warns and exits
    # 0, which reads as success to the daemon's regen trigger and to any script
    # driving this. Fail loudly instead, and name the command that fixes it.
    croak "net-gen-dnsmasq: none of the " . scalar(@$resv) . " reservation(s) fall in"
      . " a zoned subnet — refusing to write an empty config set.\n"
      . "  Tag the subnets first, e.g. net-reserve set-zone 192.168.15.0/24 dmz\n"
        if @$resv && !%by_zone;
    $warn->("net-gen-dnsmasq: zones " . join(', ',
            map { "$_.0/24=$zone_of_24{$_} [$zone_src{$_}]" } sort keys %zone_of_24)
       . "\n");

    # Which hosts have legs in MORE THAN ONE zone? Those are exactly the names
    # dnsmasq cannot answer well: the same bare name lands in several zone files
    # and dnsmasq round-robins between addresses on different segments with no
    # idea which one the asking client can reach. Under
    # [dnsmasq] multihomed = qualified, emit only zone-qualified names for them,
    # leaving the bare name out of dnsmasq's local data — dnsmasq consults that
    # data BEFORE any server=/…/ route, so leaving it in makes such a delegation
    # dead config for precisely these names.
    #
    # Legs are grouped by the MACHINE a MAC belongs to, which is what actually
    # makes them one host: nas3's third reservation is named nas3-dwn2, and only
    # the machine says that it is another nas3 leg rather than a separate device.
    # But machine records here are polluted by hostname collisions, so grouping
    # alone would rewrite the garden sensors Barrel and Beds-1 to their wrongly
    # merged machine's name. Hence the guard below: a reservation is only renamed
    # when its own name is a VARIANT of the machine's base name (nas3-dwn2 is,
    # Barrel is not), which keeps foreign entries dragged in by a bad merge under
    # the names their owners chose.

    # Compute each reservation's emitted name in two passes.
    #
    # Pass 1 groups a host's legs by the MACHINE its MAC belongs to, because
    # that is what actually makes them one host: nas3's third reservation is
    # named nas3-dwn2, and only the machine record says that is another nas3 leg
    # rather than a separate device. A reservation is renamed only when its own
    # name is a VARIANT of the machine's base name — machine records here are
    # polluted by hostname collisions, and without that guard the garden sensors
    # Barrel and Beds-1 get rewritten to their wrongly-merged machine's name.
    #
    # Pass 2 then enforces the property we actually need: NO emitted name may
    # appear in more than one zone. Pass 1 alone does not achieve it, because
    # some hosts have their legs split across separate machine records (dkctv,
    # nas5, spa2100), so their bare name still landed in two zone files and would
    # still shadow the delegation. Anything left spanning zones is qualified here
    # regardless of how its legs are recorded.
    #
    # Names are <base>-<zone>[-<n>][-air]: the zone, then an index only when a
    # host has SEVERAL legs of one adapter kind in that zone (nas3 has two wired
    # legs on .223, so nas3-home-0 and nas3-home-1), then the adapter marker.
    # -air stays LAST so it reads off the tail whatever the middle grows to, and
    # because it distinguishes legs on its own a wired/wireless pair sharing a
    # zone needs no index: u32u-home and u32u-home-air. The index follows IP
    # order so the mapping is stable between runs rather than shifting with hash
    # order. Note -up/-down are NOT zone names: they describe which way traffic
    # leaves (up = toward the Internet), which is orthogonal to which segment an
    # address is on, so they are not reused here.
    my $qualify = $a{qualify} ? 1 : 0;

    # $group_of decides which legs are ONE HOST (always the machine record, so
    # nas3-dwn2 is recognised as an nas3 leg); $emit_of is the name the file
    # would print if nothing were renamed. They must be separate: pass 2 falls
    # back to $emit_of, and using the machine there would let a polluted machine
    # record rename foreign reservations — the Barrel/Beds-1 corruption.
    my $name_map = sub {
        my ($group_of, $emit_of) = @_;
        my %out;                         # "mac|ip" -> name
        my %sfx;                         # "mac|ip" -> adapter marker ('' or -air)

        # Name one host's legs within one zone. The index distinguishes legs of
        # the SAME adapter kind only: a wired and a wireless leg on one segment
        # already read apart as u32u-home and u32u-home-air, so neither should
        # collect a -0/-1 it does not need.
        my $assign = sub {
            my ($stem, $zone, $rs) = @_;
            my %kind;
            push @{ $kind{ $sfx{ _rkey($_) } // '' } }, $_ for @$rs;
            for my $s (keys %kind) {
                my @k = sort { _ipkey($a->{ip}) <=> _ipkey($b->{ip}) } @{ $kind{$s} };
                my $i = 0;
                for my $r (@k) {
                    $out{ _rkey($r) } = "$stem-$zone" . (@k > 1 ? "-$i" : '') . $s;
                    $i++;
                }
            }
        };

        # The adapter marker is a property of the LEG, so it can only come from
        # the reservation's own name: a machine record holds one name for the
        # whole box and cannot say which of its legs is the wireless one. Taking
        # it from the machine both dropped the marker (amfpc-air -> amfpc-dmz)
        # and spread it to wired legs of a machine that happened to be recorded
        # under an -air name. Computed once here, appended last everywhere.
        $sfx{ _rkey($_) } = ( _split_iface($_->{name} // '') )[1]
            for map { @$_ } values %by_zone;

        my %legs;                        # stem -> zone -> [r]
        for my $zone (keys %by_zone) {
            for my $r (@{ $by_zone{$zone} }) {
                my ($b) = _split_iface($group_of->($r));
                next unless defined $b && length $b;
                push @{ $legs{$b}{$zone} }, $r;
            }
        }
        # pass 1 — machine-grouped legs. Splitting -air off the stem is what
        # lets a machine recorded as u32u-air group with a plain u32u leg.
        for my $base (grep { keys %{ $legs{$_} } > 1 } keys %legs) {
            for my $zone (keys %{ $legs{$base} }) {
                my @own = grep {
                    my $n = lc(( _split_iface($_->{name} // '') )[0]);
                    $n eq lc($base) || index($n, lc($base) . '-') == 0
                } @{ $legs{$base}{$zone} };
                $assign->($base, $zone, \@own) if @own;
            }
        }
        # pass 2 — anything still spanning zones under its emitted name
        my %by_emitted;
        for my $zone (keys %by_zone) {
            for my $r (@{ $by_zone{$zone} }) {
                my ($n) = _split_iface( $out{ _rkey($r) } // $emit_of->($r) );
                next unless defined $n && length $n;
                push @{ $by_emitted{$n}{$zone} }, $r;
            }
        }
        for my $n (grep { keys %{ $by_emitted{$_} } > 1 } keys %by_emitted) {
            $assign->($n, $_, $by_emitted{$n}{$_}) for keys %{ $by_emitted{$n} };
        }
        return \%out;
    };

    my $machine_of = sub { $mac2host{ lc $_[0]{mac} } // $_[0]{name} };

    # The hosts/DNS name: the MACHINE's name, so every leg of one box answers to
    # the bare name (nas3-up, nas3-dwn2 -> nas3) — but ONLY when this MAC's own
    # reservation name is a leg of that machine. Machine records here are
    # polluted by hostname collisions: machine 323 holds both an LG G4 phone and
    # wc13, so the unguarded form printed wc13's reservation as lg-g4 and wc13
    # resolved nowhere, while the dhcp-host line above still said wc13 — the same
    # MAC named two different things in the two halves of one render. When the
    # machine disagrees with the MAC, the MAC wins; identity is per-MAC here and
    # a merged machine record is not evidence about who a MAC belongs to.
    my $host_of = sub {
        my $r = shift;
        my $m = $mac2host{ lc $r->{mac} };
        return $m if defined $m && _same_host($r->{name}, $m);
        return $r->{name} // $m;      # unnamed reservation still gets the machine's
    };
    my $dh_name   = $name_map->($machine_of, sub { _short($_[0]{name} // '') });
    my $host_name = $name_map->($machine_of, $host_of);
    if (%$dh_name) {
        my %hosts = map { _dequal($_) => 1 } values %$dh_name;
        $warn->(sprintf("net-gen-dnsmasq: %d multi-homed host(s) [%s] — %s
",
                     scalar(keys %hosts), join(',', sort keys %hosts),
                     $qualify ? "emitting zone-qualified names only"
                              : "emitting the bare name in each zone; set "
                              . "[dnsmasq] multihomed = qualified to delegate them"));
    }

    my %out;
    for my $zone (sort keys %by_zone) {
        my @rs = @{ $by_zone{$zone} };

        # dnsmasq-<zone>: curated SHORT name, name-sort, dedup by MAC (keep first + warn)
        my (%seenmac, @dh);
        for my $r (sort { _short($a->{name}) cmp _short($b->{name}) or _ipkey($a->{ip}) <=> _ipkey($b->{ip}) } @rs) {
            my $mac  = lc $r->{mac};
            my $sn   = _short($r->{name});
            $sn = $dh_name->{"$mac|$r->{ip}"} if $qualify && $dh_name->{"$mac|$r->{ip}"};
            if (my $first = $seenmac{$mac}) {
                $warn->("WARN dnsmasq-$zone duplicate mac $r->{mac}: skipping '$sn' at $r->{ip} (kept $first)\n");
                next;
            }
            $seenmac{$mac} = "$sn\@" . $r->{ip};
            # layout=files -> a conf-file, whose lines are dnsmasq OPTIONS and so
            # need the `dhcp-host=` keyword. layout=dirs -> a --dhcp-hostsdir
            # BANK file, whose lines are bare option ARGUMENTS; the keyword there
            # is a syntax error logged per line, and every reservation is lost.
            push @dh, $dirs ? "$mac,$sn,$r->{ip},$lease\n"
                                     : "dhcp-host=$mac,$sn,$r->{ip},$lease\n";
        }
        $out{$zone}{dhcp} = join '', @dh;

        # hosts-<zone>: suffixed per-side machine name, IP-sort, dedup by IP (keep first + warn)
        my (%seenip, @hl);
        for my $r (sort { _ipkey($a->{ip}) <=> _ipkey($b->{ip}) } @rs) {
            if (my $first = $seenip{ $r->{ip} }) {
                $warn->("WARN hosts-$zone duplicate ip $r->{ip}: skipping (kept $first)\n");
                next;
            }
            $seenip{ $r->{ip} } = ($r->{name} // '?');
            my $mac  = lc $r->{mac};
            my $name = $host_of->($r);
            # Same rule as the dhcp-host line above: a multi-homed host must not
            # appear here under its bare name either, or the hosts file shadows
            # the delegation just as effectively as the DHCP entry would.
            $name = $host_name->{"$mac|$r->{ip}"}
                if $qualify && $host_name->{"$mac|$r->{ip}"};
            next unless defined $name && length $name;
            (my $macid = $mac) =~ s/:/_/g;
            # The MAC annotation is COMMENTED. dnsmasq's hosts parser treats every
            # whitespace-separated token after the address as another name for it
            # (cache.c gettok), so an uncommented M<mac> registers ~200 junk names
            # like M00_d8_61_34_ea_b8.grfx.com. '#' runs to end of line there
            # (cache.c eatspace), so this keeps the annotation for humans and
            # hides it from dnsmasq. Nothing in net-mgr parses it back.
            push @hl, sprintf("%-25s%s\t%s\t#M%s\n", $r->{ip}, $name, "$name.$domain", $macid);
        }
        $out{$zone}{hosts} = join '', @hl;
    }

    return { zones => \%out, zone_of_24 => \%zone_of_24, zone_src => \%zone_src,
             skipped => ($skipped || 0) };
}

1;

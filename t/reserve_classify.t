#!/usr/bin/perl
# Tests net-reserve's classify() / occupant() — the address-map state machine.
#
# classify() is pure given a gather()'d model, so these need no daemon and no
# DB: build the model by hand and assert the state. That matters because the
# case this file mainly exists for (a reserved address occupied by a DIFFERENT
# MAC) is invisible in production most of the time — it only appears when
# somebody is actually squatting, which is exactly when nobody wants to be
# discovering that the map calls it "+ in use".
use strict;
use warnings;
use FindBin;
use Test::More;

# net-reserve is a script, not a module; it returns early when `caller` is set.
require "$FindBin::Bin/../bin/net-reserve";

my $RESV_MAC = '1c:c3:ab:bc:0f:50';   # the reservation's owner
my $OTHER    = '00:08:ca:6b:14:81';   # somebody else

# Minimal model: one reservation on .171, a /24 pool .100-.199 so pool-vs-static
# is exercised too.
sub model {
    my (%o) = @_;
    return {
        ranges => [ { subnet_cidr => '192.168.15.0/24',
                      start_ip => '192.168.15.100', end_ip => '192.168.15.199' } ],
        resv     => { '192.168.15.171' => { ip => '192.168.15.171',
                                            mac => $RESV_MAC, name => 'Barrel' } },
        leased   => $o{leased}   || {},
        observed => $o{observed} || {},
        mac_name => { lc $OTHER => 'u32u-air' },
        mac_cur_ip => $o{mac_cur_ip} || {},
        mac_resv_ip => { lc $RESV_MAC => '192.168.15.171' },
        subnets  => ['192.168.15.0/24'],
    };
}

# ---- the reservation's own device is on it: in effect ------------------
{
    my $m = model(leased => { '192.168.15.171' =>
        { ip => '192.168.15.171', mac => $RESV_MAC, hostname => 'Barrel' } });
    is(classify($m, '192.168.15.171'), 'active',
       'reserved + leased by its OWN mac => active');
    unlike(occupant($m, '192.168.15.171'), qr/HELD BY/,
       'occupant does not cry conflict when the right device is home');
}

# ---- somebody else is on it: conflict, NOT active ---------------------
{
    my $m = model(leased => { '192.168.15.171' =>
        { ip => '192.168.15.171', mac => $OTHER, hostname => 'Barrel.grfx.com' } });
    is(classify($m, '192.168.15.171'), 'conflict',
       'reserved + leased by a DIFFERENT mac => conflict (was silently "active")');
    my $occ = occupant($m, '192.168.15.171');
    like($occ, qr/HELD BY/,        'occupant flags the squatter');
    like($occ, qr/u32u-air/,       'occupant names the squatter from mac_name');
    like($occ, qr/\Q$OTHER\E/,     'occupant prints the squatting mac');
}

# ---- a live observation by another mac counts too ----------------------
{
    my $m = model(observed => { '192.168.15.171' =>
        { addr => '192.168.15.171', mac => $OTHER, source => 'gateway3:arp' } });
    is(classify($m, '192.168.15.171'), 'conflict',
       'reserved + live ARP sighting of another mac => conflict');
}

# ---- a STALE observation must not manufacture a conflict --------------
{
    my $m = model(observed => { '192.168.15.171' =>
        { addr => '192.168.15.171', mac => $OTHER, source => 'nas3:net-reserve' } });
    is(classify($m, '192.168.15.171'), 'reserved',
       'a paper :net-reserve trace is not an occupant, so not a conflict');
}

# ---- an occupant with no MAC cannot be judged a squatter --------------
{
    my $m = model(leased => { '192.168.15.171' =>
        { ip => '192.168.15.171', hostname => 'mystery' } });
    is(classify($m, '192.168.15.171'), 'active',
       'lease without a mac stays active - absence of evidence is not a squatter');
}

# ---- the pre-existing states still behave ----------------------------
{
    my $m = model();
    is(classify($m, '192.168.15.171'), 'reserved', 'reserved, nothing on it');
    is(classify($m, '192.168.15.150'), 'assigned', 'inside the pool => assigned');
    is(classify($m, '192.168.15.20'),  'free',     'outside the pool => free');

    my $d = model(mac_cur_ip => { lc $RESV_MAC => '192.168.15.180' });
    is(classify($d, '192.168.15.171'), 'orphan_resv',
       'reserved device living elsewhere => orphan_resv (unchanged)');

    my $u = model(leased => { '192.168.15.150' =>
        { ip => '192.168.15.150', mac => $OTHER } });
    is(classify($u, '192.168.15.150'), 'in-use',
       'unreserved but occupied => in-use (unchanged)');
}

# ---- the new state must be renderable, not just classifiable ----------
{
    my $lbl = state_label('conflict');
    isnt($lbl, 'conflict', 'conflict has a real label, not the bare key');
    like($lbl, qr/conflict/i, 'and the label says conflict');

    ok(_state_offers_release('conflict'),
       'a conflicted cell still offers edit/release in the GUI');
    ok(!_state_offers_release('free'), 'a free cell offers reserve, not release');

    # %COLOR/%GLYPH are file-scoped lexicals in the script, so they cannot be
    # read from here. Check the source instead: a state missing from them prints
    # '?' on a piped map and vanishes from the legend, which is precisely how a
    # new state ships half-finished — worth catching even via a coarse grep.
    open my $fh, '<', "$FindBin::Bin/../bin/net-reserve" or die $!;
    my $src = do { local $/; <$fh> };
    close $fh;
    for my $tbl (qw(COLOR GLYPH)) {
        my ($blk) = $src =~ /my \%$tbl = \((.*?)\n\);/s;
        ok($blk && $blk =~ /\bconflict\b\s*=>/, "\%$tbl has a conflict entry");
    }
    like($src, qr/qw\(free assigned in-use reserved orphan_resv active conflict\)/,
         'CLI legend lists conflict');
}

done_testing();

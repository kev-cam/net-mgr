package NetMgr::Election;
# Pure decision function. Given:
#   - self's identity + scoring inputs
#   - mesh snapshot (every peer's last-known {role, priority, master})
#   - local peer_caps table (who *we* think is allowed to be master)
# Returns the role this daemon should adopt right now:
#   { role => 'master'|'follower'|'auto',
#     master_member => 'kc-qernel' | '',
#     reachable, roster_n, quorum_ok,
#     score, reason }
#
# This was previously the body of net-mgr-relay's run_election(),
# which probed each member via short-lived STATUS connections every
# 60s. Slice C made the mesh push role/priority/master in every
# heartbeat (every 5s), so the same decision can fire any time a
# heartbeat lands or a peer drops — no probes needed.
#
# Pure / no IO so it's trivially unit-testable.

use strict;
use warnings;
use Time::HiRes ();

sub decide {
    my (%args) = @_;

    my $self_name  = $args{self_name}  // 'self';
    my $self_state = $args{self_state} || {};
    my $mesh       = $args{mesh_snap}  || {};
    my $peer_caps  = $args{peer_caps}  || {};
    my $roster_n   = $args{roster_n};
    my $hb_dead    = $args{hb_dead}    // 30;
    my $now        = $args{now}        // time;

    # Build candidate list: self + every mesh peer with a recent HB.
    my @cands = ({
        member          => $self_name,
        role            => $self_state->{role}            // 'auto',
        priority        => $self_state->{priority}        // 100,
        prefer_lan      => exists $self_state->{prefer_lan}
                           ? $self_state->{prefer_lan} : 1,
        internet_facing => $self_state->{internet_facing} // 0,
        is_self         => 1,
    });
    for my $name (sort keys %$mesh) {
        my $p = $mesh->{$name};
        next if $p->{unconfigured};
        # Only count peers whose heartbeat is fresh; a dropped peer
        # shouldn't keep its old role/priority alive in the election.
        next unless $p->{last_hb_rx} > 0
                 && ($now - $p->{last_hb_rx}) < $hb_dead;
        my $rem = $p->{remote} || {};
        push @cands, {
            member          => $name,
            role            => $rem->{role}            // 'auto',
            priority        => defined $rem->{priority}
                               ? $rem->{priority} + 0 : 100,
            # Peers don't broadcast prefer_lan / internet_facing in
            # the HB (yet). Treat as 'prefer LAN, not internet-facing'
            # — the historical default that wins the score tie.
            prefer_lan      => 1,
            internet_facing => 0,
        };
    }

    my $reachable = scalar @cands;          # self always counted
    $roster_n //= $reachable;
    my $quorum_ok = ($roster_n <= 1) ? 1
                                     : ($reachable >= int($roster_n / 2) + 1);

    # Eligibility filter.
    my $caps_configured = $peer_caps && %$peer_caps;
    my @eligible;
    for my $c (@cands) {
        my $role = $c->{role} // 'auto';
        next if $role eq 'excluded';
        next if $role eq 'follower';     # opted out of being master
        if ($caps_configured) {
            my $granted = $peer_caps->{ $c->{member} } || [];
            next unless grep { $_ eq 'master' } @$granted;
        }
        $c->{score} = _score($c->{priority},
                             $c->{prefer_lan},
                             $c->{internet_facing});
        push @eligible, $c;
    }

    if (!$quorum_ok) {
        return _result('auto', '', undef,
                       "no quorum ($reachable/$roster_n)",
                       $reachable, $roster_n, $quorum_ok);
    }
    if (!@eligible) {
        return _result('auto', '', undef,
                       "no eligible candidates",
                       $reachable, $roster_n, $quorum_ok);
    }

    @eligible = sort {
           $a->{score} <=> $b->{score}
        || $a->{member} cmp $b->{member}
    } @eligible;
    my $winner = $eligible[0];
    my $role   = $winner->{is_self} ? 'master' : 'follower';
    return _result($role, $winner->{member}, $winner->{score},
                   "winner=$winner->{member} score=$winner->{score}",
                   $reachable, $roster_n, $quorum_ok);
}

# Score: lower is better. Matches the historical relay scoring so
# transition is observation-invariant.
sub _score {
    my ($priority, $prefer_lan, $internet_facing) = @_;
    my $s = ($priority // 100) + 0;
    $s -= 50 if $prefer_lan && !$internet_facing;
    return $s;
}

sub _result {
    my ($role, $master, $score, $reason, $reach, $roster, $quorum) = @_;
    return {
        role          => $role,
        master_member => $master,
        score         => $score,
        reason        => $reason,
        reachable     => $reach,
        roster_n      => $roster,
        quorum_ok     => $quorum,
    };
}

1;

#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::Where qw(parse eval_ast);

sub matches {
    my ($expr, $row) = @_;
    my $ast = parse($expr);
    return eval_ast($ast, $row);
}

# --- basic equality / inequality ---------------------------------------
{
    my $row = { mac => 'aa:bb:cc:dd:ee:01', ip => '192.168.15.42', online => 1 };
    is(matches("mac = 'aa:bb:cc:dd:ee:01'", $row), 1, 'string equality');
    is(matches("mac = 'aa:bb:cc:dd:ee:02'", $row), 0, 'string inequality');
    is(matches("mac != 'aa:bb:cc:dd:ee:02'", $row), 1, '!= true');
    is(matches("online = 1", $row), 1, 'numeric equality');
    is(matches("online = 0", $row), 0, 'numeric mismatch');
}

# --- LIKE --------------------------------------------------------------
{
    my $row = { ip => '192.168.15.42', host => 'kestrel.grfx.com' };
    is(matches("ip LIKE '192.168.15.%'", $row), 1, 'LIKE prefix');
    is(matches("ip LIKE '192.168.16.%'", $row), 0, 'LIKE no match');
    is(matches("host LIKE '%.grfx.com'", $row), 1, 'LIKE suffix');
    is(matches("host LIKE 'kestrel.____.com'", $row), 1, 'LIKE underscore');
    is(matches("host NOT LIKE '%.example.com'", $row), 1, 'NOT LIKE');
    # case-insensitive (MySQL default for non-binary)
    is(matches("host LIKE 'KESTREL.%'", $row), 1, 'LIKE case-insensitive');
}

# --- IN ----------------------------------------------------------------
{
    my $row = { type => 'device_new' };
    is(matches("type IN ('device_new','device_offline')", $row), 1, 'IN match');
    is(matches("type IN ('foo','bar')", $row), 0, 'IN miss');
    is(matches("type NOT IN ('foo','bar')", $row), 1, 'NOT IN match');
}

# --- AND / OR / NOT / parens ------------------------------------------
{
    my $row = { ip => '192.168.15.42', vendor => 'Intel', online => 1 };
    is(matches("ip LIKE '192.168.15.%' AND vendor = 'Intel'", $row), 1, 'AND');
    is(matches("ip LIKE '192.168.16.%' OR vendor = 'Intel'", $row), 1, 'OR rhs');
    is(matches("NOT (online = 0)", $row), 1, 'NOT parens');
    is(matches("(ip LIKE '10.%' OR ip LIKE '192.168.15.%') AND online = 1", $row), 1, 'parens grouping');
}

# --- IS NULL / IS NOT NULL --------------------------------------------
{
    my $row = { mac => 'aa:bb:cc:dd:ee:01', machine_id => undef };
    is(matches("machine_id IS NULL", $row), 1, 'IS NULL true');
    is(matches("mac IS NULL", $row), 0, 'IS NULL false on present');
    is(matches("mac IS NOT NULL", $row), 1, 'IS NOT NULL');
    is(matches("missing_col IS NULL", $row), 1, 'missing column is null');
}

# --- numeric comparisons ----------------------------------------------
{
    my $row = { signal => -54, port => 22 };
    is(matches("signal > -60", $row), 1, '> with negative');
    is(matches("signal < -60", $row), 0, '< with negative');
    is(matches("port >= 22 AND port <= 1024", $row), 1, 'range');
}

# --- now() / ago() / interval -----------------------------------------
{
    my $now = time();
    my $row = { last_seen => $now - 30 };
    is(matches("last_seen > now() - 60",                    $row), 1, 'now() arithmetic');
    is(matches("last_seen > now() - interval 1 minute",     $row), 1, 'interval minute');
    is(matches("last_seen > now() - interval 5 second",     $row), 0, 'interval second');
    is(matches("last_seen > ago(60)",                       $row), 1, 'ago()');
    is(matches("last_seen < ago(10)",                       $row), 1, 'ago() lt');
}

# --- IPv6-shaped addresses --------------------------------------------
{
    my $row = { addr => 'fe80::aabb:ccff:fedd:ee01', family => 'v6' };
    is(matches("family = 'v6' AND addr LIKE 'fe80::%'", $row), 1, 'v6 link-local match');
    is(matches("family = 'v4'", $row), 0, 'v4 mismatch');
}

# --- NULL comparison semantics ----------------------------------------
{
    my $row = { hostname => undef };
    is(matches("hostname = 'foo'",       $row), 0, 'NULL = string is false');
    is(matches("hostname != 'foo'",      $row), 0, 'NULL != string is false');
    is(matches("hostname IS NULL",       $row), 1, 'NULL IS NULL');
    is(matches("hostname LIKE 'f%'",     $row), 0, 'NULL LIKE is false');
}

# --- case-insensitive identifiers and keywords -----------------------
{
    my $row = { Online => 1, IP => '10.0.0.1' };
    is(matches("online = 1", $row), 1, 'identifier case-insensitive');
    is(matches("IP like '10.%'", $row), 1, 'lowercase keyword');
}

# --- empty / undef input ---------------------------------------------
{
    is(parse(undef), undef, 'parse(undef) returns undef');
    is(parse(""),    undef, 'parse("") returns undef');
}

# --- malformed input throws -----------------------------------------
{
    eval { parse("ip = ") };           ok($@, 'missing rhs throws');
    eval { parse("(ip = 1") };         ok($@, 'unbalanced paren throws');
    eval { parse("foo(bar)") };        ok($@, 'unknown function throws');
    eval { parse("ip ~~ 1") };         ok($@, 'unknown operator throws');
    eval { parse("ip = 1 garbage") };  ok($@, 'trailing tokens throw');
}

done_testing;

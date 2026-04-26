#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::Protocol qw(parse_line format_ok format_err format_ready
                        format_row format_eos format_kv);

# ---- HELLO ------------------------------------------------------------
{
    my $c = parse_line("HELLO source=nmap pid=12345");
    is($c->{verb}, 'HELLO');
    is($c->{kv}{source}, 'nmap');
    is($c->{kv}{pid}, '12345');
}
{
    my $c = parse_line("HELLO consumer=net-show.7821");
    is($c->{kv}{consumer}, 'net-show.7821', 'consumer name with dot');
}

# ---- OBSERVE / GONE ---------------------------------------------------
{
    my $c = parse_line('OBSERVE mac=aa:bb:cc:dd:ee:01 ip=192.168.15.42 ports=22,80');
    is($c->{verb}, 'OBSERVE');
    is($c->{kv}{mac}, 'aa:bb:cc:dd:ee:01', 'mac with colons');
    is($c->{kv}{ports}, '22,80', 'commas allowed in bare values');
}
{
    my $c = parse_line('OBSERVE vendor="Intel Corp"');
    is($c->{kv}{vendor}, 'Intel Corp', 'quoted value with space');
}
{
    my $c = parse_line('OBSERVE vendor="says ""hi"" friends"');
    is($c->{kv}{vendor}, 'says "hi" friends', 'doubled-quote escape');
}
{
    my $c = parse_line('GONE mac=aa:bb:cc:dd:ee:01 via=ap:wndr1');
    is($c->{verb}, 'GONE');
    is($c->{kv}{via}, 'ap:wndr1');
}

# ---- TRIGGER ----------------------------------------------------------
{
    my $c = parse_line("TRIGGER scan-ap WAIT");
    is($c->{verb}, 'TRIGGER');
    is($c->{name}, 'scan-ap');
    is($c->{wait}, 1);
}
{
    my $c = parse_line("TRIGGER probe-host mac=aa:bb:cc:dd:ee:01");
    is($c->{name}, 'probe-host');
    is($c->{wait}, 0);
    is($c->{kv}{mac}, 'aa:bb:cc:dd:ee:01');
}

# ---- SUBSCRIBE --------------------------------------------------------
{
    my $c = parse_line("SUBSCRIBE sub=1 mode=snapshot FROM aps");
    is($c->{verb}, 'SUBSCRIBE');
    is($c->{sub}, 1);
    is($c->{mode}, 'snapshot');
    is($c->{table}, 'aps');
    is($c->{where}, undef, 'no WHERE');
}
{
    my $c = parse_line("SUBSCRIBE sub=2 mode=stream FROM events WHERE type IN ('device_new','device_offline') AND ip LIKE '192.168.15.%'");
    is($c->{sub}, 2);
    is($c->{mode}, 'stream');
    is($c->{table}, 'events');
    like($c->{where}, qr/type IN/, 'WHERE preserved');
    like($c->{where}, qr/192\.168\.15/, 'WHERE preserved fully');
}
{
    my $c = parse_line("SUBSCRIBE sub=3 mode=snapshot+stream FROM machines");
    is($c->{mode}, 'snapshot+stream');
}

# ---- UNSUB / BYE ------------------------------------------------------
{
    my $c = parse_line("UNSUB sub=2");
    is($c->{verb}, 'UNSUB');
    is($c->{sub}, 2);
}
{
    my $c = parse_line("BYE");
    is($c->{verb}, 'BYE');
}

# ---- comments / blank lines ------------------------------------------
{
    is(parse_line("# a comment"), undef, 'comment ignored');
    is(parse_line(""), undef, 'empty line ignored');
    is(parse_line("   "), undef, 'whitespace-only ignored');
    is(parse_line(undef), undef, 'undef ignored');
}

# ---- malformed -------------------------------------------------------
{
    eval { parse_line("FROBNICATE foo=bar") };  ok($@, 'unknown verb');
    eval { parse_line("OBSERVE no-eq") };       ok($@, 'OBSERVE missing =');
    eval { parse_line("SUBSCRIBE sub=1") };      ok($@, 'SUBSCRIBE missing FROM');
    eval { parse_line("SUBSCRIBE mode=snapshot FROM aps") }; ok($@, 'SUBSCRIBE missing sub');
    eval { parse_line('OBSERVE k="oops')   };   ok($@, 'unterminated quote');
    eval { parse_line('UNSUB')             };   ok($@, 'UNSUB missing sub');
}

# ---- formatters ------------------------------------------------------
is(format_ok(),                          'OK',                    'OK bare');
is(format_ok(took => '1.2'),             'OK took=1.2',           'OK with kv');
is(format_err("bad thing"),              'ERR bad thing',         'ERR');
is(format_err("bad\nthing"),             'ERR bad thing',         'ERR strips newline');
is(format_ready(id => 1),                'READY id=1',            'READY');
is(format_eos(2),                        'EOS sub=2',              'EOS');

# row formatting + roundtrip — sub=N for subscription handle, kv for the row
{
    my $line = format_row(1, 'aps', 'update',
                          id => 42,                  # row's own id column
                          mac => 'aa:bb:cc:dd:ee:01',
                          ssid => 'home net');
    like($line, qr/^ROW /,                   'starts with ROW');
    like($line, qr/sub=1/,                   'has sub');
    like($line, qr/table=aps/,               'has table');
    like($line, qr/op=update/,               'has op');
    like($line, qr/id=42/,                   'row id preserved separately');
    like($line, qr/ssid="home net"/,         'quoted ssid');
    my $c = parse_line($line);
    is($c->{verb}, 'ROW');
    is($c->{kv}{sub}, '1',                   'sub parsed back');
    is($c->{kv}{id},  '42',                  'row id parsed back');
    is($c->{kv}{ssid}, 'home net',           'roundtrip quoted');
}

# kv with empty string
is(format_kv(x => ''), 'x=""', 'empty quoted');

# kv skips undef
is(format_kv(a => 'x', b => undef, c => 'y'), 'a=x c=y', 'undef skipped');

done_testing;

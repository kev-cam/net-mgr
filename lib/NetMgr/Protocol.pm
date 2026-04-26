package NetMgr::Protocol;
# Line-based wire protocol for net-mgr.
#
# Verbs (client → server):
#   HELLO     source=<n> [pid=N]            -- producer identification
#   HELLO     consumer=<n> [pid=N]          -- subscriber identification
#   OBSERVE   k=v ...                       -- producer observation
#   GONE      k=v ...                       -- producer explicit disappearance
#   TRIGGER   <name> [k=v ...] [WAIT]       -- RPC, optional synchronous
#   SUBSCRIBE sub=N mode=<m> FROM <table> [WHERE <expr>]
#   UNSUB     sub=N
#   BYE
#
# Replies (server → client):
#   OK [k=v ...]
#   ERR  <msg>
#   READY [sub=N] [k=v ...]
#   ROW   sub=N table=<t> op=<insert|update|delete|snapshot> k=v ...
#   EOS   sub=N
#
# `sub=N` (subscription handle) is used everywhere instead of `id=N` so
# it can't clash with a row's own `id` column when serialised in ROW.
#
# Tokens are whitespace-separated. Values may be bare (no whitespace,
# no quote, no '=', no parens) or double-quoted with "" to escape ".
# Bare values may contain commas (for things like ports=22,80) — the
# parser doesn't split on them.
#
# WHERE clause: everything after the WHERE token, passed verbatim to
# NetMgr::Where for parsing.

use strict;
use warnings;
use Carp qw(croak);
use Exporter 'import';

our @EXPORT_OK = qw(parse_line format_ok format_err format_ready
                    format_row format_eos format_kv);

sub parse_line {
    my ($line) = @_;
    return undef unless defined $line;
    $line =~ s/[\r\n]+\z//;
    $line =~ s/^\s+//;
    return undef if $line eq '' || $line =~ /^#/;

    # SUBSCRIBE has WHERE-clause tail; strip it before kv parsing
    my $where_clause;
    if ($line =~ /^\s*SUBSCRIBE\b/i && $line =~ /\bWHERE\b/i) {
        if ($line =~ s/\s+WHERE\s+(.*)$//i) {
            $where_clause = $1;
        }
    }

    my @toks = _tokenize($line);
    croak "empty command" unless @toks;

    my $verb = uc shift @toks;
    my $cmd  = { verb => $verb };

    if    ($verb eq 'HELLO')     { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'OBSERVE')   { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'GONE')      { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'BYE')       { croak "BYE takes no args" if @toks }
    elsif ($verb eq 'UNSUB') {
        my $kv = _parse_kv_only(\@toks);
        croak "UNSUB requires sub=" unless defined $kv->{sub};
        $cmd->{sub} = $kv->{sub} + 0;
    }
    elsif ($verb eq 'TRIGGER') {
        croak "TRIGGER requires a name" unless @toks;
        $cmd->{name} = shift @toks;
        $cmd->{wait} = 0;
        my @rest;
        for my $t (@toks) {
            if (uc $t eq 'WAIT') { $cmd->{wait} = 1 } else { push @rest, $t }
        }
        $cmd->{kv} = _parse_kv_only(\@rest);
    }
    elsif ($verb eq 'SUBSCRIBE') {
        # Expect: id=N mode=<m> FROM <table>
        # Pre-WHERE the tokenizer keeps FROM as a bare token.
        my $kv = {};
        my $table;
        while (@toks) {
            my $t = shift @toks;
            if (uc $t eq 'FROM') {
                croak "expected table after FROM" unless @toks;
                $table = shift @toks;
            }
            elsif ($t =~ /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s) {
                $kv->{$1} = $2;
            }
            else {
                croak "unexpected SUBSCRIBE token '$t'";
            }
        }
        croak "SUBSCRIBE requires sub="         unless defined $kv->{sub};
        croak "SUBSCRIBE requires mode="        unless defined $kv->{mode};
        croak "SUBSCRIBE requires FROM <table>" unless defined $table;
        my $mode = lc $kv->{mode};
        croak "bad mode '$mode'"
            unless $mode =~ /^(snapshot|stream|snapshot\+stream)$/;
        $cmd->{sub}   = $kv->{sub} + 0;
        $cmd->{mode}  = $mode;
        $cmd->{table} = $table;
        $cmd->{where} = $where_clause if defined $where_clause;
    }
    elsif ($verb eq 'OK' || $verb eq 'ERR' || $verb eq 'READY'
        || $verb eq 'ROW' || $verb eq 'EOS') {
        # server-originated; parse for clients that want to consume them
        if ($verb eq 'ERR') {
            $cmd->{msg} = join ' ', @toks;
        } else {
            $cmd->{kv} = _parse_kv_only(\@toks);
        }
    }
    else {
        croak "unknown verb '$verb'";
    }

    return $cmd;
}

sub _parse_kv_only {
    my ($toks) = @_;
    my %kv;
    for my $t (@$toks) {
        croak "expected k=v, got '$t'"
            unless $t =~ /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;
        $kv{$1} = $2;
    }
    return \%kv;
}

# Tokenize one logical command line.
# Handles bare tokens (no whitespace/quote/paren), quoted strings ("..."),
# and the equals sign as part of a single token (foo="bar baz").
sub _tokenize {
    my ($line) = @_;
    my @toks;
    my $i = 0;
    my $n = length $line;
    while ($i < $n) {
        my $c = substr($line, $i, 1);
        if ($c =~ /\s/) { $i++; next }
        if ($c eq '"') {
            # standalone quoted token (rare — usually quoted values appear
            # after =), but handle it for robustness
            my ($val, $next) = _read_quoted($line, $i);
            push @toks, $val;
            $i = $next;
            next;
        }
        # bare token, possibly with a key= prefix and a quoted value
        my $start = $i;
        while ($i < $n) {
            my $cc = substr($line, $i, 1);
            last if $cc =~ /\s/;
            if ($cc eq '=' && $i+1 < $n && substr($line,$i+1,1) eq '"') {
                # consume up to and including =, then read quoted value
                my $key = substr($line, $start, $i - $start);
                my ($val, $next) = _read_quoted($line, $i+1);
                push @toks, "$key=$val";
                $i = $next;
                $start = -1;
                last;
            }
            $i++;
        }
        if ($start >= 0) {
            push @toks, substr($line, $start, $i - $start);
        }
    }
    return @toks;
}

sub _read_quoted {
    my ($s, $i) = @_;
    croak "expected '\"'" unless substr($s, $i, 1) eq '"';
    $i++;
    my $val = '';
    my $n = length $s;
    while ($i < $n) {
        my $c = substr($s, $i, 1);
        if ($c eq '"') {
            if ($i+1 < $n && substr($s, $i+1, 1) eq '"') {
                $val .= '"'; $i += 2; next;
            }
            return ($val, $i+1);
        }
        $val .= $c; $i++;
    }
    croak "unterminated quoted string";
}

# ---- formatters ---------------------------------------------------------

sub format_kv {
    my %h = @_;
    my @parts;
    for my $k (sort keys %h) {
        my $v = $h{$k};
        next unless defined $v;
        push @parts, "$k=" . _quote_if_needed($v);
    }
    return join ' ', @parts;
}

sub _quote_if_needed {
    my ($v) = @_;
    return '""' if !length $v;
    if ($v =~ /[\s"=()]/) {
        my $q = $v;
        $q =~ s/"/""/g;
        return qq("$q");
    }
    return $v;
}

sub format_ok    { my %h = @_; my $kv = format_kv(%h); return $kv ? "OK $kv" : "OK" }
sub format_err   { my $m = shift // ''; $m =~ s/[\r\n]+/ /g; return "ERR $m" }
sub format_ready { my %h = @_; return "READY " . format_kv(%h) }
sub format_eos   { my ($sub) = @_; return "EOS sub=$sub" }

# format_row($sub_id, $table, $op, %row) — keeps the subscription id
# (`sub=`) separate from the row columns so a row's own `id` column
# doesn't clobber it.
sub format_row {
    my ($sub_id, $table, $op, %row) = @_;
    my $head = "sub=$sub_id table=$table op=$op";
    my $tail = format_kv(%row);
    return $tail ? "ROW $head $tail" : "ROW $head";
}

1;

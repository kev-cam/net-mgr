package NetMgr::Where;
# WHERE-clause subset for net-mgr SUBSCRIBE filters.
#
# Grammar (recursive descent):
#   expr     := or_expr
#   or_expr  := and_expr ( OR and_expr )*
#   and_expr := not_expr ( AND not_expr )*
#   not_expr := NOT not_expr | atom
#   atom     := '(' expr ')' | predicate
#   predicate:= sum  ( cmp_op sum
#                    | LIKE str | NOT LIKE str
#                    | IN '(' list ')' | NOT IN '(' list ')'
#                    | IS [NOT] NULL )
#   sum      := term ( ('+'|'-') term )*
#   term     := primary ( ('*'|'/') primary )*
#   primary  := number | string | identifier | func | '(' sum ')' | INTERVAL n unit
#   func     := 'now' '(' ')' | 'ago' '(' sum ')'
#
# Returns AST as nested arrayrefs: [op, ...]. Evaluate with eval_ast($ast, \%row).
#
# Identifier lookup: column name in the row hashref; missing = undef.
# Strings: single- or double-quoted; '' or "" escape inside. Doubled quotes.
# LIKE: SQL %_ wildcards, case-insensitive (MySQL default).
# now()/ago(n)/interval N unit: seconds since epoch / now()-n / N*unit_seconds.
# Time columns are expected to be epoch seconds in the row hash.

use strict;
use warnings;
use Carp qw(croak);
use Exporter 'import';

our @EXPORT_OK = qw(parse eval_ast);

my %INTERVAL_UNIT = (
    second => 1,        seconds => 1,         sec => 1,
    minute => 60,       minutes => 60,        min => 60,
    hour   => 3600,     hours   => 3600,
    day    => 86400,    days    => 86400,
    week   => 604800,   weeks   => 604800,
);

sub parse {
    my ($src) = @_;
    return undef unless defined $src && length $src;
    my $self = bless { src => $src, toks => _tokenize($src), pos => 0 }, __PACKAGE__;
    my $ast = $self->_parse_or;
    croak "trailing tokens at end of WHERE: " . _show_remaining($self)
        if $self->{pos} < @{ $self->{toks} };
    return $ast;
}

# ---- tokenizer ----------------------------------------------------------

sub _tokenize {
    my ($s) = @_;
    my @t;
    pos($s) = 0;
    while (pos($s) < length $s) {
        if    ($s =~ /\G\s+/gc)                 { next }
        elsif ($s =~ /\G(--[^\n]*|\#[^\n]*)/gc) { next }   # comment
        elsif ($s =~ /\G(\d+(?:\.\d+)?)/gc)     { push @t, ['num', $1+0] }
        elsif ($s =~ /\G'((?:[^']|'')*)'/gc)    { my $v=$1; $v=~s/''/'/g; push @t, ['str', $v] }
        elsif ($s =~ /\G"((?:[^"]|"")*)"/gc)    { my $v=$1; $v=~s/""/"/g; push @t, ['str', $v] }
        elsif ($s =~ /\G(<=|>=|<>|!=|=|<|>)/gc) { push @t, ['op', $1 eq '<>' ? '!=' : $1] }
        elsif ($s =~ /\G([(),+\-*\/])/gc)       { push @t, ['punct', $1] }
        elsif ($s =~ /\G([A-Za-z_][A-Za-z0-9_]*)/gc) {
            my $w = $1; my $u = uc $w;
            if    ($u eq 'AND')      { push @t, ['kw','AND'] }
            elsif ($u eq 'OR')       { push @t, ['kw','OR'] }
            elsif ($u eq 'NOT')      { push @t, ['kw','NOT'] }
            elsif ($u eq 'LIKE')     { push @t, ['kw','LIKE'] }
            elsif ($u eq 'IN')       { push @t, ['kw','IN'] }
            elsif ($u eq 'IS')       { push @t, ['kw','IS'] }
            elsif ($u eq 'NULL')     { push @t, ['kw','NULL'] }
            elsif ($u eq 'TRUE')     { push @t, ['num', 1] }
            elsif ($u eq 'FALSE')    { push @t, ['num', 0] }
            elsif ($u eq 'INTERVAL') { push @t, ['kw','INTERVAL'] }
            else                     { push @t, ['ident', $w] }
        }
        else {
            my $here = substr($s, pos($s), 16);
            croak "unexpected char in WHERE near '$here'";
        }
    }
    return \@t;
}

sub _peek    { my $s=shift; $s->{toks}[ $s->{pos} ] }
sub _peek2   { my $s=shift; $s->{toks}[ $s->{pos}+1 ] }
sub _advance { my $s=shift; $s->{toks}[ $s->{pos}++ ] }
sub _show_remaining {
    my $s = shift;
    my @rem = @{ $s->{toks} }[ $s->{pos} .. $#{ $s->{toks} } ];
    return join ' ', map { ref $_ ? join(':',@$_) : $_ } @rem[0..($#rem<3?$#rem:3)];
}

sub _match_kw {
    my ($s, $kw) = @_;
    my $t = _peek($s);
    if ($t && $t->[0] eq 'kw' && $t->[1] eq $kw) { _advance($s); return 1 }
    return 0;
}
sub _expect_punct {
    my ($s, $p) = @_;
    my $t = _peek($s);
    croak "expected '$p'" unless $t && $t->[0] eq 'punct' && $t->[1] eq $p;
    _advance($s);
}

# ---- parser -------------------------------------------------------------

sub _parse_or {
    my $s = shift;
    my $a = $s->_parse_and;
    while (_match_kw($s,'OR')) {
        my $b = $s->_parse_and;
        $a = ['or', $a, $b];
    }
    return $a;
}

sub _parse_and {
    my $s = shift;
    my $a = $s->_parse_not;
    while (_match_kw($s,'AND')) {
        my $b = $s->_parse_not;
        $a = ['and', $a, $b];
    }
    return $a;
}

sub _parse_not {
    my $s = shift;
    if (_match_kw($s,'NOT')) {
        return ['not', $s->_parse_not];
    }
    return $s->_parse_atom;
}

sub _parse_atom {
    my $s = shift;
    my $t = _peek($s);
    croak "unexpected end of WHERE" unless $t;

    # parenthesized boolean (or sum — disambiguate by trying boolean first)
    if ($t->[0] eq 'punct' && $t->[1] eq '(') {
        # peek past the paren — if the next token is a boolean keyword path,
        # treat as boolean group; else fall through to predicate (which will
        # consume the paren as part of a sum).
        # Simpler: try predicate-first since predicate's sum handles parens.
        return $s->_parse_predicate;
    }
    return $s->_parse_predicate;
}

sub _parse_predicate {
    my $s = shift;
    my $lhs = $s->_parse_sum;

    my $t = _peek($s);
    return ['truthy', $lhs] unless $t;   # bare expr — truthiness

    if ($t->[0] eq 'op') {
        _advance($s);
        my $rhs = $s->_parse_sum;
        return [$t->[1], $lhs, $rhs];
    }
    if ($t->[0] eq 'kw') {
        if ($t->[1] eq 'LIKE')  { _advance($s); return ['like',  $lhs, $s->_parse_sum] }
        if ($t->[1] eq 'NOT' && _peek2($s) && _peek2($s)->[0] eq 'kw') {
            my $n = _peek2($s)->[1];
            if ($n eq 'LIKE') { _advance($s); _advance($s); return ['nlike', $lhs, $s->_parse_sum] }
            if ($n eq 'IN')   { _advance($s); _advance($s); return ['nin',   $lhs, $s->_parse_list] }
        }
        if ($t->[1] eq 'IN')    { _advance($s); return ['in',    $lhs, $s->_parse_list] }
        if ($t->[1] eq 'IS') {
            _advance($s);
            my $neg = _match_kw($s,'NOT');
            croak "expected NULL after IS" unless _match_kw($s,'NULL');
            return [$neg ? 'isnotnull' : 'isnull', $lhs];
        }
    }
    return ['truthy', $lhs];
}

sub _parse_list {
    my $s = shift;
    _expect_punct($s, '(');
    my @items;
    push @items, $s->_parse_sum;
    while (1) {
        my $t = _peek($s);
        last unless $t && $t->[0] eq 'punct' && $t->[1] eq ',';
        _advance($s);
        push @items, $s->_parse_sum;
    }
    _expect_punct($s, ')');
    return ['list', \@items];
}

sub _parse_sum {
    my $s = shift;
    my $a = $s->_parse_term;
    while (1) {
        my $t = _peek($s);
        last unless $t && $t->[0] eq 'punct' && ($t->[1] eq '+' || $t->[1] eq '-');
        _advance($s);
        my $b = $s->_parse_term;
        $a = [$t->[1], $a, $b];
    }
    return $a;
}

sub _parse_term {
    my $s = shift;
    my $a = $s->_parse_primary;
    while (1) {
        my $t = _peek($s);
        last unless $t && $t->[0] eq 'punct' && ($t->[1] eq '*' || $t->[1] eq '/');
        _advance($s);
        my $b = $s->_parse_primary;
        $a = [$t->[1], $a, $b];
    }
    return $a;
}

sub _parse_primary {
    my $s = shift;
    my $t = _peek($s);
    croak "unexpected end" unless $t;

    if ($t->[0] eq 'num')   { _advance($s); return ['num', $t->[1]] }
    if ($t->[0] eq 'str')   { _advance($s); return ['str', $t->[1]] }
    if ($t->[0] eq 'kw' && $t->[1] eq 'NULL') { _advance($s); return ['null'] }
    if ($t->[0] eq 'kw' && $t->[1] eq 'INTERVAL') {
        _advance($s);
        my $n = _peek($s);
        croak "expected number after INTERVAL" unless $n && $n->[0] eq 'num';
        _advance($s);
        my $u = _peek($s);
        croak "expected unit after INTERVAL <n>" unless $u && $u->[0] eq 'ident';
        my $secs = $INTERVAL_UNIT{ lc $u->[1] };
        croak "unknown interval unit '$u->[1]'" unless defined $secs;
        _advance($s);
        return ['num', $n->[1] * $secs];
    }
    if ($t->[0] eq 'punct' && $t->[1] eq '-') {
        _advance($s);
        return ['-', ['num', 0], $s->_parse_primary];
    }
    if ($t->[0] eq 'punct' && $t->[1] eq '(') {
        _advance($s);
        # could be a sub-expression of a sum, or a parenthesized boolean
        my $inner = $s->_parse_or;
        _expect_punct($s, ')');
        return $inner;
    }
    if ($t->[0] eq 'ident') {
        my $name = $t->[1];
        _advance($s);
        my $nx = _peek($s);
        if ($nx && $nx->[0] eq 'punct' && $nx->[1] eq '(') {
            _advance($s);
            if (lc $name eq 'now') {
                _expect_punct($s, ')');
                return ['fn_now'];
            }
            if (lc $name eq 'ago') {
                my $arg = $s->_parse_sum;
                _expect_punct($s, ')');
                return ['fn_ago', $arg];
            }
            croak "unknown function '$name'";
        }
        return ['col', $name];
    }
    croak "unexpected token in primary: " . join(':', @$t);
}

# ---- evaluator ----------------------------------------------------------

sub eval_ast {
    my ($ast, $row) = @_;
    return _ev($ast, $row);
}

sub _ev {
    my ($n, $row) = @_;
    return undef unless defined $n;
    my $op = $n->[0];

    if ($op eq 'num' || $op eq 'str') { return $n->[1] }
    if ($op eq 'null')                { return undef }
    if ($op eq 'col') {
        # case-insensitive column lookup against the row hash
        return undef unless ref $row eq 'HASH';
        return $row->{ $n->[1] } if exists $row->{ $n->[1] };
        my $lc = lc $n->[1];
        for my $k (keys %$row) { return $row->{$k} if lc $k eq $lc }
        return undef;
    }
    if ($op eq 'fn_now') { return time() }
    if ($op eq 'fn_ago') { my $v = _ev($n->[1], $row); return time() - ($v // 0) }

    if ($op eq '+' || $op eq '-' || $op eq '*' || $op eq '/') {
        my $a = _ev($n->[1], $row);
        my $b = _ev($n->[2], $row);
        return undef unless defined $a && defined $b;
        return $a + $b if $op eq '+';
        return $a - $b if $op eq '-';
        return $a * $b if $op eq '*';
        return $b == 0 ? undef : $a / $b;
    }

    if ($op eq 'and') { my $a=_ev($n->[1],$row); return $a ? (_ev($n->[2],$row) ? 1 : 0) : 0 }
    if ($op eq 'or')  { my $a=_ev($n->[1],$row); return $a ? 1 : (_ev($n->[2],$row) ? 1 : 0) }
    if ($op eq 'not') { my $a=_ev($n->[1],$row); return $a ? 0 : 1 }

    if ($op eq 'truthy') { return _ev($n->[1],$row) ? 1 : 0 }

    if ($op eq '=' || $op eq '!=' || $op eq '<' || $op eq '<=' || $op eq '>' || $op eq '>=') {
        my $a = _ev($n->[1], $row);
        my $b = _ev($n->[2], $row);
        # NULL semantics: any comparison with NULL is false (SQL UNKNOWN→false here).
        return 0 unless defined $a && defined $b;
        my $numeric = (_isnum($a) && _isnum($b));
        my $cmp;
        if ($numeric) { $cmp = $a <=> $b } else { $cmp = $a cmp $b }
        return ($op eq '=')  ? ($cmp == 0 ? 1 : 0)
             : ($op eq '!=') ? ($cmp != 0 ? 1 : 0)
             : ($op eq '<')  ? ($cmp <  0 ? 1 : 0)
             : ($op eq '<=') ? ($cmp <= 0 ? 1 : 0)
             : ($op eq '>')  ? ($cmp >  0 ? 1 : 0)
             :                 ($cmp >= 0 ? 1 : 0);
    }
    if ($op eq 'like' || $op eq 'nlike') {
        my $a = _ev($n->[1], $row);
        my $p = _ev($n->[2], $row);
        return 0 unless defined $a && defined $p;
        my $re = _like_to_regex($p);
        my $m  = ($a =~ $re) ? 1 : 0;
        return $op eq 'like' ? $m : 1 - $m;
    }
    if ($op eq 'in' || $op eq 'nin') {
        my $a = _ev($n->[1], $row);
        return 0 unless defined $a;
        my $list = $n->[2];
        my $found = 0;
        for my $item (@{ $list->[1] }) {
            my $v = _ev($item, $row);
            next unless defined $v;
            if (_isnum($a) && _isnum($v)) { if ($a == $v) { $found = 1; last } }
            else                          { if ($a eq $v) { $found = 1; last } }
        }
        return $op eq 'in' ? $found : ($found ? 0 : 1);
    }
    if ($op eq 'isnull')    { return defined _ev($n->[1], $row) ? 0 : 1 }
    if ($op eq 'isnotnull') { return defined _ev($n->[1], $row) ? 1 : 0 }
    if ($op eq 'list')      { croak "list used outside of IN" }

    croak "unknown AST op '$op'";
}

sub _isnum {
    my $v = shift;
    return 0 unless defined $v;
    return $v =~ /^-?\d+(?:\.\d+)?$/ ? 1 : 0;
}

sub _like_to_regex {
    my ($pat) = @_;
    my $re = '';
    for (my $i = 0; $i < length $pat; $i++) {
        my $c = substr($pat, $i, 1);
        if    ($c eq '%') { $re .= '.*' }
        elsif ($c eq '_') { $re .= '.'  }
        else              { $re .= quotemeta $c }
    }
    return qr/\A${re}\z/i;
}

1;

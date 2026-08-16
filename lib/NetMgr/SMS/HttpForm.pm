package NetMgr::SMS::HttpForm;
# Generic HTTP SMS provider: you describe the request, this makes it.
#
# Deliberately NOT one module per service. NumberBarn, Google Voice and the
# LTE router's admin UI have no stable documented SMS API between them, and
# hardcoding a guessed endpoint produces something that looks fine until the
# night it has to work. Instead the request is config: whoever knows what the
# service actually wants writes it down once, and can verify it with curl by
# hand first.
#
#   [provider:numberbarn]
#   type        = http
#   url         = https://api.example.com/v1/messages
#   method      = POST                       # default POST
#   content_type= application/json           # default application/x-www-form-urlencoded
#   body        = {"to":"{to}","text":"{text}","from":"{user}"}
#   header      = X-Api-Key: {pass}          # repeatable via header1..header9
#   secret      = numberbarn                 # /etc/net-mgr/secrets/numberbarn = "user:pass"
#   ok_status   = 200,201,202                # default: any 2xx
#   ok_match    = "status"\s*:\s*"sent"      # optional regex the body must match
#   timeout     = 15
#   needs_net   = 1                          # default 1; set 0 for a LAN device
#
# Placeholders in url/body/header: {to} {text} {user} {pass}. {text} and {to}
# are percent-encoded in url= and in a form body; in a JSON body they are
# JSON-escaped instead, chosen by content_type.
#
# Credentials never live in this file — `secret` names a root-owned 600 file
# under /etc/net-mgr/secrets holding "user:pass" (see NetMgr::Secret).

use strict;
use warnings;
use NetMgr::Secret;

sub new {
    my ($class, %a) = @_;
    my $cfg = $a{cfg} || {};
    die "url is required\n" unless defined $cfg->{url} && length $cfg->{url};
    return bless { name => $a{name}, cfg => $cfg }, $class;
}

sub type { 'http' }

# A LAN-side device (the LTE router, a local gateway) does NOT need internet —
# that is exactly why it is worth having in the chain. Default 1 because most
# entries here will be web services.
sub needs_net {
    my ($self) = @_;
    return exists $self->{cfg}{needs_net} ? ($self->{cfg}{needs_net} ? 1 : 0) : 1;
}

sub available {
    my ($self) = @_;
    return (0, 'curl not in PATH') unless _which('curl');
    if (my $s = $self->{cfg}{secret}) {
        my (undef, undef, $err) = NetMgr::Secret::get_userpass($s);
        return (0, "secret '$s': $err") if $err;
    }
    return (1, '');
}

sub send {
    my ($self, $to, $text) = @_;
    my $c    = $self->{cfg};
    my $curl = _which('curl') or return (0, 'curl not found');
    my ($user, $pass) = ('', '');
    if (my $s = $c->{secret}) {
        my ($u, $p, $err) = NetMgr::Secret::get_userpass($s);
        return (0, "secret '$s': $err") if $err;
        ($user, $pass) = ($u // '', $p // '');
    }

    my $ctype = $c->{content_type} // 'application/x-www-form-urlencoded';
    my $json  = $ctype =~ m{json}i ? 1 : 0;
    my %ph = (to => $to, text => $text, user => $user, pass => $pass);

    my $url  = _fill($c->{url},  \%ph, 1, 0);          # url: always percent-encode
    my $body = defined $c->{body} ? _fill($c->{body}, \%ph, !$json, $json) : undef;

    my @cmd = ($curl, '-sS', '-o', '-', '-w', '\n%{http_code}',
               '--max-time', ($c->{timeout} // 15));
    push @cmd, '-X', uc($c->{method} // ($body ? 'POST' : 'GET'));
    push @cmd, '-H', "Content-Type: $ctype" if defined $body;
    for my $k ('header', map { "header$_" } 1..9) {
        next unless defined $c->{$k} && length $c->{$k};
        push @cmd, '-H', _fill($c->{$k}, \%ph, 0, 0);
    }
    push @cmd, '--data-binary', $body if defined $body;
    push @cmd, $url;

    my $out = _run(@cmd);
    return (0, 'curl produced no output') unless defined $out;
    my ($code) = $out =~ /(\d{3})\s*$/;
    $code //= 0;
    (my $bodyout = $out) =~ s/\n?\d{3}\s*$//;

    if (my $want = $c->{ok_status}) {
        my %w = map { $_ => 1 } grep { length } split /\s*,\s*/, $want;
        return (0, "http $code") unless $w{$code};
    }
    elsif ($code !~ /^2\d\d$/) {
        return (0, "http $code");
    }
    if (my $re = $c->{ok_match}) {
        return (0, "http $code but body did not match ok_match")
            unless $bodyout =~ /$re/;
    }
    return (1, "http $code");
}

# $enc: percent-encode the substituted value. $jsonesc: JSON-escape instead.
# Credentials are substituted the same way as anything else, but note they are
# never returned in the detail string, so a failure line can be logged safely.
sub _fill {
    my ($tmpl, $ph, $enc, $jsonesc) = @_;
    my $out = $tmpl;
    for my $k (keys %$ph) {
        my $v = $ph->{$k};
        $v = defined $v ? $v : '';
        if    ($jsonesc) { $v =~ s/(["\\])/\\$1/g; $v =~ s/\n/\\n/g; $v =~ s/\r/\\r/g; $v =~ s/\t/\\t/g }
        elsif ($enc)     { $v =~ s/([^A-Za-z0-9._~\-])/sprintf('%%%02X', ord $1)/ge }
        $out =~ s/\{\Q$k\E\}/$v/g;
    }
    return $out;
}

sub _run {
    my @cmd = @_;
    my $pid = open(my $fh, '-|');
    return undef unless defined $pid;
    if (!$pid) { open STDERR, '>', '/dev/null'; exec @cmd; exit 127 }
    local $/;
    my $o = <$fh>;
    close $fh;
    return $o;
}

sub _which {
    my ($p) = @_;
    for my $d (split /:/, ($ENV{PATH} // '')) {
        return "$d/$p" if -x "$d/$p";
    }
    return undef;
}

1;

package NetMgr::ChatArchive;
# Per-chat on-disk archive. When an owner closes a session its messages are
# MOVED out of the DB into <base>/<name>/:
#   messages.jsonl   one JSON object per message — round-trips back on resurrect
#   session.json     session metadata + members (so the archive is self-contained)
#   transcript.txt   human-readable render
#   files/           uploaded files (phase 2)
# The directory persists until explicitly deleted; the chat_sessions row stays
# so owners can find and resurrect it. Reopening restores messages.jsonl.

use strict;
use warnings;
use Carp qw(croak);
use JSON::PP ();
use File::Path qw(make_path);
use File::Spec;

my $JSON = JSON::PP->new->utf8->canonical;

# A chat name is validated [A-Za-z0-9][A-Za-z0-9._-]* by the protocol, so it is
# a single safe path segment; re-check here so a bad name can never escape.
sub dir {
    my ($base, $name) = @_;
    croak "bad chat name '" . ($name // '') . "'"
        unless defined $base && length $base
            && defined $name && $name =~ /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/;
    return File::Spec->catdir($base, $name);
}

sub messages_path   { File::Spec->catfile(dir(@_), 'messages.jsonl') }
sub session_path    { File::Spec->catfile(dir(@_), 'session.json') }
sub transcript_path { File::Spec->catfile(dir(@_), 'transcript.txt') }
sub files_dir       { File::Spec->catdir(dir(@_), 'files') }

sub has_archive { return -f messages_path(@_) }

# Write the archive for a session. $messages is an arrayref of message hashes
# (id, ts, sender, sender_kind, body, in_reply_to). Returns the directory.
sub write_archive {
    my ($base, $session, $members, $messages) = @_;
    my $name = $session->{name} or croak "session name required";
    my $d = dir($base, $name);
    make_path($d, files_dir($base, $name));

    _spew(session_path($base, $name),
        $JSON->encode({ session => $session, members => ($members || []) }) . "\n");

    open my $mf, '>:encoding(UTF-8)', messages_path($base, $name)
        or croak "write " . messages_path($base, $name) . ": $!";
    for my $m (@$messages) {
        print {$mf} $JSON->encode({
            map { ($_ => $m->{$_}) } qw(id ts sender sender_kind body in_reply_to)
        }), "\n";
    }
    close $mf or croak "close messages.jsonl: $!";

    open my $tf, '>:encoding(UTF-8)', transcript_path($base, $name)
        or croak "write " . transcript_path($base, $name) . ": $!";
    my $topic = (defined $session->{topic} && length $session->{topic})
        ? " \x{2014} $session->{topic}" : '';
    print {$tf} "# chat '$name'$topic\n";
    for my $m (@$messages) {
        my $ts = $m->{ts} // ''; $ts =~ s/\.\d+$//;
        printf {$tf} "%s  %s: %s\n", $ts, ($m->{sender} // '?'), ($m->{body} // '');
    }
    close $tf or croak "close transcript.txt: $!";

    return $d;
}

# Read archived messages back (arrayref of hashes), for resurrect.
sub read_messages {
    my ($base, $name) = @_;
    my $p = messages_path($base, $name);
    return [] unless -f $p;
    open my $fh, '<:encoding(UTF-8)', $p or croak "read $p: $!";
    my @msgs;
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my $m = eval { $JSON->decode($line) } or next;
        push @msgs, $m;
    }
    close $fh;
    return \@msgs;
}

sub _spew {
    my ($path, $data) = @_;
    open my $fh, '>:encoding(UTF-8)', $path or croak "write $path: $!";
    print {$fh} $data;
    close $fh or croak "close $path: $!";
}

1;

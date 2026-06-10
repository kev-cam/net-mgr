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

# No ->utf8: encode/decode work on character strings, and the file handles
# (all opened :encoding(UTF-8)) do the bytes<->chars. (utf8 + an encoding layer
# would double-encode.)
my $JSON = JSON::PP->new->canonical;

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

# A filename within a chat's files/ dir: one safe segment, no path parts.
sub safe_filename {
    my ($name) = @_;
    return (defined $name && $name =~ /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/
            && $name ne '..') ? $name : undef;
}

# Absolute path to an uploaded file, creating the files/ dir. Dies on a bad
# filename so nothing can be written outside the chat's directory.
sub file_path {
    my ($base, $session, $filename) = @_;
    my $fn = safe_filename($filename)
        or croak "bad file name '" . ($filename // '') . "'";
    my $d = files_dir($base, $session);
    make_path($d) unless -d $d;
    return File::Spec->catfile($d, $fn);
}

# List uploaded files as ({ name, size, mtime }, …), name-sorted.
sub list_files {
    my ($base, $session) = @_;
    my $d = files_dir($base, $session);
    return [] unless -d $d;
    opendir my $dh, $d or return [];
    my @files;
    for my $f (sort grep { !/^\./ } readdir $dh) {
        my $p = File::Spec->catfile($d, $f);
        next unless -f $p;
        my @st = stat $p;
        push @files, { name => $f, size => $st[7], mtime => $st[9] };
    }
    closedir $dh;
    return \@files;
}

# Remove one uploaded file. Validates the name (so it can only ever unlink
# <base>/<session>/files/<safe-name>). Returns 1 if removed, 0 if absent.
sub delete_file {
    my ($base, $session, $filename) = @_;
    my $fn = safe_filename($filename)
        or croak "bad file name '" . ($filename // '') . "'";
    my $p = File::Spec->catfile(files_dir($base, $session), $fn);
    return 0 unless -f $p;
    unlink $p or croak "unlink $p: $!";
    return 1;
}

# Remove a chat's whole archive directory (messages + files). Validates the
# name (so it can only ever remove <base>/<safe-name>) and no-ops if absent.
sub delete_archive {
    my ($base, $name) = @_;
    my $d = dir($base, $name);          # croaks on a bad name
    return 0 unless -d $d;
    File::Path::remove_tree($d);
    return 1;
}

sub _spew {
    my ($path, $data) = @_;
    open my $fh, '>:encoding(UTF-8)', $path or croak "write $path: $!";
    print {$fh} $data;
    close $fh or croak "close $path: $!";
}

1;

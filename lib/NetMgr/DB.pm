package NetMgr::DB;
# DBI wrapper for net-mgr. Connects via /root/.my.cnf [<section>],
# bootstraps the schema if absent, and exposes UPSERT helpers that
# return change-info so the daemon can emit transition events.

use strict;
use warnings;
use Carp qw(croak);
use DBI;
use FindBin;

our $SCHEMA_VERSION = 3;

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        defaults_file => $args{defaults_file} // '/root/.my.cnf',
        section       => $args{section}       // 'net-mgr',
        db            => $args{db}            // 'netmgr',
        schema_dir    => $args{schema_dir}    // "$FindBin::Bin/../sql",
        dbh           => undef,
    }, $class;
    return $self;
}

sub connect {
    my ($self) = @_;
    croak "defaults file '$self->{defaults_file}' not readable"
        unless -r $self->{defaults_file};
    my $dsn = "DBI:mysql:database=$self->{db}"
            . ";mysql_read_default_file=$self->{defaults_file}"
            . ";mysql_read_default_group=$self->{section}";
    my $dbh = DBI->connect($dsn, undef, undef, {
        RaiseError           => 1,
        PrintError           => 0,
        AutoCommit           => 1,
        mysql_enable_utf8mb4 => 1,
        mysql_auto_reconnect => 1,   # idle-drop survivability for the daemon
    });
    $self->{dbh} = $dbh;
    return $self;
}

sub dbh { $_[0]->{dbh} }

sub disconnect {
    my ($self) = @_;
    if ($self->{dbh}) { $self->{dbh}->disconnect; $self->{dbh} = undef }
}

# ---- schema bootstrap ---------------------------------------------------

sub current_schema_version {
    my ($self) = @_;
    my $exists = $self->{dbh}->selectrow_array(
        "SELECT COUNT(*) FROM information_schema.tables
          WHERE table_schema = DATABASE() AND table_name = 'schema_version'"
    );
    return 0 unless $exists;
    my ($v) = $self->{dbh}->selectrow_array(
        "SELECT MAX(version) FROM schema_version"
    );
    return $v // 0;
}

sub bootstrap_schema {
    my ($self) = @_;
    my $cur = $self->current_schema_version;
    return $cur if $cur >= $SCHEMA_VERSION;

    if ($cur == 0) {
        # Fresh install — load schema.sql wholesale.
        my $path = "$self->{schema_dir}/schema.sql";
        open my $fh, '<', $path or croak "open $path: $!";
        my $sql = do { local $/; <$fh> };
        close $fh;
        my @stmts = split /;\s*\n/, $sql;
        for my $s (@stmts) {
            $s =~ s/^\s+|\s+$//g;
            next if $s eq '' || $s =~ /^--/;
            $self->{dbh}->do($s);
        }
        return $self->current_schema_version;
    }

    # Incremental migrations from $cur to $SCHEMA_VERSION.
    while ($cur < $SCHEMA_VERSION) {
        my $next = $cur + 1;
        $self->_apply_migration($next);
        $self->{dbh}->do("INSERT IGNORE INTO schema_version (version) VALUES (?)",
                         undef, $next);
        $cur = $next;
    }
    return $self->current_schema_version;
}

# Per-version DDL migrations. Inline rather than separate files for now —
# add a sql/migrations/ tree if/when the count justifies it.
sub _apply_migration {
    my ($self, $v) = @_;
    if ($v == 2) {
        # Add addresses.source so we can track where each (mac, addr)
        # assignment came from (DHCP server, dhcp.master, dhcp.extra, nmap).
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD COLUMN source VARCHAR(64) AFTER addr"
        );
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD KEY idx_source (source)"
        );
        return;
    }
    if ($v == 3) {
        # Add aliases for explicit name → (machine, preferred-subnet) overrides
        # used by the DNS resolver. machine_id FK with cascade delete.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS aliases (
    name               VARCHAR(255) NOT NULL PRIMARY KEY,
    machine_id         INT          NOT NULL,
    prefer_subnet_cidr VARCHAR(45),
    source             VARCHAR(64),
    notes              TEXT,
    created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_alias_machine (machine_id),
    CONSTRAINT fk_alias_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    croak "no migration for schema v$v";
}

# ---- UPSERT helpers ----------------------------------------------------
# Each returns: { op => 'insert'|'update'|'noop', changed_fields => [..],
#                 was => \%before|undef, now => \%after }

sub upsert_interface {
    my ($self, %f) = @_;
    croak "mac required" unless $f{mac};
    $f{mac} = lc $f{mac};

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interfaces WHERE mac = ?", undef, $f{mac}
    );
    if ($was) {
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(machine_id vendor kind online)) {
            next unless exists $f{$k};
            my $old = $was->{$k};
            my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set,  "$k = ?";
            push @bind, $new;
        }
        push @set,  "last_seen = CURRENT_TIMESTAMP";
        my $sql = "UPDATE interfaces SET " . join(', ', @set) . " WHERE mac = ?";
        $self->{dbh}->do($sql, undef, @bind, $f{mac});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM interfaces WHERE mac = ?", undef, $f{mac});
        return {
            op             => @changed ? 'update' : 'noop',
            changed_fields => \@changed,
            was            => $was,
            now            => $now,
        };
    }

    $self->{dbh}->do(
        "INSERT INTO interfaces (mac, machine_id, vendor, kind, online)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{mac}, $f{machine_id}, $f{vendor}, ($f{kind} // 'unknown'),
        ($f{online} // 0)
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interfaces WHERE mac = ?", undef, $f{mac});
    return { op => 'insert', changed_fields => [keys %$now], was => undef, now => $now };
}

sub upsert_address {
    my ($self, %f) = @_;
    croak "mac required"    unless $f{mac};
    croak "addr required"   unless $f{addr};
    croak "family required" unless $f{family};
    $f{mac} = lc $f{mac};

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND family = ? AND addr = ?",
        undef, $f{mac}, $f{family}, $f{addr}
    );
    if ($was) {
        my @changed;
        # Only overwrite source when the new authority is >= the existing one.
        # That way a casual nmap observation can't downgrade a dhcp.master entry.
        my $new_src = $f{source};
        if (defined $new_src
            && _source_priority($new_src) >= _source_priority($was->{source})
            && (($was->{source} // '') ne $new_src))
        {
            push @changed, 'source';
            $self->{dbh}->do(
                "UPDATE addresses SET source = ?, last_seen = CURRENT_TIMESTAMP
                  WHERE mac = ? AND family = ? AND addr = ?",
                undef, $new_src, $f{mac}, $f{family}, $f{addr}
            );
        } else {
            $self->{dbh}->do(
                "UPDATE addresses SET last_seen = CURRENT_TIMESTAMP
                  WHERE mac = ? AND family = ? AND addr = ?",
                undef, $f{mac}, $f{family}, $f{addr}
            );
        }
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM addresses WHERE mac = ? AND family = ? AND addr = ?",
            undef, $f{mac}, $f{family}, $f{addr}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO addresses (mac, family, addr, source) VALUES (?, ?, ?, ?)",
        undef, $f{mac}, $f{family}, $f{addr}, $f{source}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND family = ? AND addr = ?",
        undef, $f{mac}, $f{family}, $f{addr}
    );
    return { op => 'insert', changed_fields => [qw(mac family addr source)],
             was => undef, now => $now };
}

# Higher = more authoritative. The exact strings are convention; the suffix
# after the colon classifies the source.
sub _source_priority {
    my ($s) = @_;
    return 0 unless defined $s;
    return 5 if $s =~ /:dhcp\.master$/;
    return 4 if $s =~ /:dhcp\.extra$/;
    return 3 if $s =~ /:DHCP$/i;       # leased from a DHCP server
    return 3 if $s =~ /:ssh$/i;        # direct probe of host (e.g. AP self-report)
    return 1 if $s =~ /:(arp|nmap)$/i; # passive observation
    return 1;
}

sub upsert_machine {
    my ($self, %f) = @_;
    if ($f{id}) {
        my $was = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM machines WHERE id = ?", undef, $f{id});
        return { op => 'noop', was => undef, now => undef } unless $was;
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(primary_name online notes)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set,  "$k = ?";
            push @bind, $new;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do(
            "UPDATE machines SET " . join(', ', @set) . " WHERE id = ?",
            undef, @bind, $f{id});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM machines WHERE id = ?", undef, $f{id});
        return {
            op             => @changed ? 'update' : 'noop',
            changed_fields => \@changed,
            was            => $was,
            now            => $now,
        };
    }

    $self->{dbh}->do(
        "INSERT INTO machines (primary_name, online, notes) VALUES (?, ?, ?)",
        undef, $f{primary_name}, ($f{online} // 0), $f{notes}
    );
    my $id  = $self->{dbh}->{mysql_insertid};
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM machines WHERE id = ?", undef, $id);
    return { op => 'insert', changed_fields => [keys %$now],
             was => undef, now => $now };
}

sub upsert_hostname {
    my ($self, %f) = @_;
    croak "machine_id, name, source required"
        unless $f{machine_id} && $f{name} && $f{source};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM hostnames
          WHERE machine_id = ? AND name = ? AND source = ?",
        undef, $f{machine_id}, $f{name}, $f{source}
    );
    if ($was) {
        $self->{dbh}->do(
            "UPDATE hostnames SET last_seen = CURRENT_TIMESTAMP
              WHERE machine_id = ? AND name = ? AND source = ?",
            undef, $f{machine_id}, $f{name}, $f{source}
        );
        return { op => 'noop', changed_fields => [],
                 was => $was, now => $was };
    }
    $self->{dbh}->do(
        "INSERT INTO hostnames (machine_id, name, source) VALUES (?, ?, ?)",
        undef, $f{machine_id}, $f{name}, $f{source}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM hostnames
          WHERE machine_id = ? AND name = ? AND source = ?",
        undef, $f{machine_id}, $f{name}, $f{source}
    );
    return { op => 'insert', changed_fields => [qw(machine_id name source)],
             was => undef, now => $now };
}

sub upsert_port {
    my ($self, %f) = @_;
    croak "mac, port required" unless $f{mac} && defined $f{port};
    $f{mac}   = lc $f{mac};
    $f{proto} //= 'tcp';

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM ports WHERE mac = ? AND port = ? AND proto = ?",
        undef, $f{mac}, $f{port}, $f{proto}
    );
    if ($was) {
        my @changed;
        if (exists $f{service} && (($was->{service} // '') ne ($f{service} // ''))) {
            push @changed, 'service';
            $self->{dbh}->do(
                "UPDATE ports SET service = ?, last_seen = CURRENT_TIMESTAMP
                  WHERE mac = ? AND port = ? AND proto = ?",
                undef, $f{service}, $f{mac}, $f{port}, $f{proto}
            );
        } else {
            $self->{dbh}->do(
                "UPDATE ports SET last_seen = CURRENT_TIMESTAMP
                  WHERE mac = ? AND port = ? AND proto = ?",
                undef, $f{mac}, $f{port}, $f{proto}
            );
        }
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM ports WHERE mac = ? AND port = ? AND proto = ?",
            undef, $f{mac}, $f{port}, $f{proto}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO ports (mac, port, proto, service) VALUES (?, ?, ?, ?)",
        undef, $f{mac}, $f{port}, $f{proto}, $f{service}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM ports WHERE mac = ? AND port = ? AND proto = ?",
        undef, $f{mac}, $f{port}, $f{proto}
    );
    return { op => 'insert', changed_fields => [qw(port service)],
             was => undef, now => $now };
}

sub upsert_ap {
    my ($self, %f) = @_;
    croak "mac required" unless $f{mac};
    $f{mac} = lc $f{mac};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
    if ($was) {
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(ssid model board)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, "$k = ?";
            push @bind, $new;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do("UPDATE aps SET " . join(', ', @set) . " WHERE mac = ?",
            undef, @bind, $f{mac});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO aps (mac, ssid, model, board) VALUES (?, ?, ?, ?)",
        undef, $f{mac}, $f{ssid}, $f{model}, $f{board}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
    return { op => 'insert', changed_fields => [qw(ssid model board)],
             was => undef, now => $now };
}

sub upsert_association {
    my ($self, %f) = @_;
    croak "ap_mac, client_mac required" unless $f{ap_mac} && $f{client_mac};
    $f{ap_mac}     = lc $f{ap_mac};
    $f{client_mac} = lc $f{client_mac};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM associations WHERE ap_mac = ? AND client_mac = ?",
        undef, $f{ap_mac}, $f{client_mac}
    );
    if ($was) {
        my @set;
        my @bind;
        my @changed;
        for my $k (qw(signal iface)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, ($k eq 'signal' ? "`signal` = ?" : "$k = ?");
            push @bind, $new;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do(
            "UPDATE associations SET " . join(', ', @set)
            . " WHERE ap_mac = ? AND client_mac = ?",
            undef, @bind, $f{ap_mac}, $f{client_mac}
        );
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM associations WHERE ap_mac = ? AND client_mac = ?",
            undef, $f{ap_mac}, $f{client_mac}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO associations (ap_mac, client_mac, `signal`, iface)
         VALUES (?, ?, ?, ?)", undef,
        $f{ap_mac}, $f{client_mac}, $f{signal}, $f{iface}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM associations WHERE ap_mac = ? AND client_mac = ?",
        undef, $f{ap_mac}, $f{client_mac}
    );
    return { op => 'insert', changed_fields => [qw(ap_mac client_mac signal iface)],
             was => undef, now => $now };
}

sub upsert_lease {
    my ($self, %f) = @_;
    croak "mac, ip required" unless $f{mac} && $f{ip};
    $f{mac} = lc $f{mac};
    my $exp;
    if (defined $f{expires}) {
        # accept epoch seconds; convert to DATETIME
        if ($f{expires} =~ /^\d+$/) {
            my @t = localtime($f{expires});
            $exp = sprintf "%04d-%02d-%02d %02d:%02d:%02d",
                $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0];
        } else { $exp = $f{expires} }
    }

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_leases WHERE mac = ? AND ip = ?",
        undef, $f{mac}, $f{ip}
    );
    if ($was) {
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(hostname ap_mac)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, "$k = ?";
            push @bind, $new;
        }
        if (defined $exp && (($was->{expires} // '') ne $exp)) {
            push @changed, 'expires';
            push @set, "expires = ?";
            push @bind, $exp;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do(
            "UPDATE dhcp_leases SET " . join(', ', @set)
            . " WHERE mac = ? AND ip = ?",
            undef, @bind, $f{mac}, $f{ip}
        );
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM dhcp_leases WHERE mac = ? AND ip = ?",
            undef, $f{mac}, $f{ip}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO dhcp_leases (mac, ip, hostname, expires, ap_mac)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{mac}, $f{ip}, $f{hostname}, $exp, $f{ap_mac}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_leases WHERE mac = ? AND ip = ?",
        undef, $f{mac}, $f{ip}
    );
    return { op => 'insert', changed_fields => [qw(mac ip hostname expires ap_mac)],
             was => undef, now => $now };
}

sub log_event {
    my ($self, %f) = @_;
    croak "type required" unless $f{type};
    $self->{dbh}->do(
        "INSERT INTO events (type, machine_id, mac, addr, details)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{type}, $f{machine_id}, ($f{mac} ? lc $f{mac} : undef),
        $f{addr}, $f{details}
    );
    return $self->{dbh}->{mysql_insertid};
}

# ---- reads -------------------------------------------------------------

sub get_interface_by_mac {
    my ($self, $mac) = @_;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interfaces WHERE mac = ?", undef, lc $mac
    );
}

sub upsert_alias {
    my ($self, %f) = @_;
    croak "name and machine_id required"
        unless defined $f{name} && defined $f{machine_id};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aliases WHERE name = ?", undef, $f{name});
    if ($was) {
        my @set; my @bind; my @changed;
        for my $k (qw(machine_id prefer_subnet_cidr source notes)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, "$k = ?";
            push @bind, $new;
        }
        return { op => 'noop', changed_fields => [], was => $was, now => $was }
            unless @changed;
        $self->{dbh}->do(
            "UPDATE aliases SET " . join(', ', @set) . " WHERE name = ?",
            undef, @bind, $f{name});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM aliases WHERE name = ?", undef, $f{name});
        return { op => 'update', changed_fields => \@changed,
                 was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO aliases (name, machine_id, prefer_subnet_cidr, source, notes)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{name}, $f{machine_id}, $f{prefer_subnet_cidr},
        $f{source}, $f{notes});
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aliases WHERE name = ?", undef, $f{name});
    return { op => 'insert',
             changed_fields => [qw(name machine_id prefer_subnet_cidr source notes)],
             was => undef, now => $now };
}

sub delete_alias {
    my ($self, $name) = @_;
    return $self->{dbh}->do("DELETE FROM aliases WHERE name = ?", undef, $name);
}

sub query_table {
    my ($self, $table, $cols) = @_;
    my %allowed = map { $_ => 1 } qw(
        machines hostnames interfaces addresses ports aps
        associations dhcp_leases events aliases
    );
    croak "unknown table '$table'" unless $allowed{$table};
    my $sql = $cols ? "SELECT " . join(', ', @$cols) . " FROM $table"
                    : "SELECT * FROM $table";
    return $self->{dbh}->selectall_arrayref($sql, { Slice => {} });
}

1;

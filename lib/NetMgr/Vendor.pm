package NetMgr::Vendor;
# Shorten OUI vendor strings (e.g. "Amazon Technologies Inc." → "Amazon")
# for compact display. Mappings ported from /usr/local/bin/scan-network.
# Use NetMgr::Vendor::shorten($vendor) at producer time so the DB stores
# the short form directly.
#
# An optional override file at /etc/net-mgr/vendors can add or replace
# entries. Format: one `pattern = short` per line, '#' comments, blank
# lines ignored. Pattern is matched case-insensitive against the
# vendor string.

use strict;
use warnings;
use Exporter 'import';

our @EXPORT_OK = qw(shorten load_overrides);

# Built-in defaults (case-insensitive). Order matters: longest prefix first
# would be ideal, but we just iterate and match any pattern as a substring
# for simplicity. Actual scan-network used /pattern$/i — anchored at end.
my @DEFAULTS = (
    # [pattern (case-insens regex), short]
    ['Amazon Technologies Inc.',                  'Amazon'],
    ['American Power Conversion',                 'APC'],
    ['AMERICAN POWER CONVERSION CORP',            'APC'],
    ['Western Digital',                           'WD'],
    ['WESTERN DIGITAL',                           'WD'],
    ['Elitegroup Computer Systems Co.',           'Elite'],
    ['Elitegroup Computer Systems',               'Elite'],
    ['Cisco-Linksys',                             'Linksys'],
    ['Cisco Systems',                             'Cisco'],
    ['Intel Corporate',                           'Intel'],
    ['Hewlett Packard',                           'HP'],
    ['D-Link International',                      'D-Link'],
    ['D-Link Corporation',                        'D-Link'],
    ['LinkSprite Technologies',                   'LinkSprite'],
    ['Shenzhen Reecam Tech.Ltd.',                 'ShenzRecam'],
    ['ASUSTek COMPUTER INC.',                     'AsusTek'],
    ['Asustek Computer',                          'AsusTek'],
    ['LodgeNet Entertainment',                    'Lodgenet'],
    ['Realtek Semiconductor corp.',               'Realtek'],
    ['Realtek Semiconductor',                     'Realtek'],
    ['Speed Dragon Multimedia Limited',           'Dragon'],
    ['TP-Link Corporation Limited',               'TP-Link'],
    ['TP-LINK TECHNOLOGIES CO.',                  'TP-Link'],
    ['Tp-link Technologies',                      'TP-Link'],
    ['PC Partner Ltd.',                           'PC Partner'],
    ['PC Partner',                                'PC-Partner'],
    ['YAMAHA CORPORATION',                        'Yamaha'],
    ['Ralink Technology Corp',                    'Ralink'],
    ['Ralink Technology',                         'Ralink'],
    ['BIOSTAR Microtech Int\'l Corp.',            'Biostar'],
    ['Biostar Microtech Int\'l',                  'Biostar'],
    ['JK microsystems',                           'JK micro.'],
    ['NETGEAR',                                   'Netgear'],
    ['Samsung Electronics Co.',                   'Samsung'],
    ['Samsung Electronics',                       'Samsung'],
    ['PLUS  Corporation',                         'PLUS Corp'],
    ['Plus',                                      'PLUS Corp'],
    ['LG Electronics (Mobile Communications)',    'LG'],
    ['TAIFATECH INC.TAIFATECH INC.',              'TaifaTech'],
    ['TAIFATECH INC.',                            'TaifaTech'],
    ['a2i marketing center',                      'A2I'],
    ['Rivet Networks',                            'Rivet'],
    ['FUJITSU LIMITED',                           'Fujitsu'],
    ['Murata Manufacturing Co.',                  'Murata'],
    ['Murata Manufacturing',                      'Murata'],
    ['Wistron Infocomm .Zhongshan. Corporation',  'Wistron'],
    ['Wistron Infocomm (Zhongshan) Corporation',  'Wistron'],
    ['Wistron InfoComm.Kunshan.Co.',              'Wistron'],
    ['Wistron InfoComm(Kunshan)Co.',              'Wistron'],
    ['Wistron Infocomm .Zhongshan.',              'Wistron'],
    ['Liteon Technology Corporation',             'Liteon'],
    ['Liteon Technology',                         'Liteon'],
    ['SHARP Corporation',                         'Sharp'],
    ['Ieee Registration Authority',               'IEEE'],
    ['Arcadyan Corporation',                      'Arcadyan'],
    ['Espressif Inc.',                            'Espressif'],
    ['China Dragon Technology Limited',           'China Dragon'],
    ['Comcast Cable Corporation',                 'Comcast'],
    ['AzureWave Technology',                      'AzureWave'],
    ['Multitech Systems',                         'Multitech'],
    ['OnePlus Technology (Shenzhen) Co.',         'One+'],
    ['iRobot Corporation',                        'iRobot'],
    ['MMB Research Inc.',                         'NMB'],
    ['JRC TOKKI Co.',                             'Tokki'],
);

my @overrides;
my $loaded_path;

# Load /etc/net-mgr/vendors if present. Idempotent.
sub load_overrides {
    my ($path) = @_;
    $path //= '/etc/net-mgr/vendors';
    return if defined $loaded_path && $loaded_path eq $path;
    $loaded_path = $path;
    @overrides = ();
    return unless -f $path;
    open my $fh, '<', $path or return;
    while (my $line = <$fh>) {
        $line =~ s/[\r\n]+\z//;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        if ($line =~ /^(.*?)\s*=\s*(.*)$/) {
            push @overrides, [$1, $2];
        }
    }
    close $fh;
}

# shorten($v) — return the short form, or $v unchanged if no rule matches.
# Override entries take precedence over defaults; both match as a tail
# anchored regex (`/$pat$/i`) so trailing punctuation differences match
# the same canonical entry.
sub shorten {
    my ($v) = @_;
    return $v unless defined $v && length $v;
    load_overrides() unless defined $loaded_path;
    for my $pair (@overrides, @DEFAULTS) {
        my ($pat, $short) = @$pair;
        my $re = qr/\Q$pat\E\z/i;
        if ($v =~ $re) {
            my $out = $v;
            $out =~ s/$re/$short/;
            return $out;
        }
    }
    return $v;
}

1;

#!/bin/bash
#
# install-guacamole.sh — put Apache Guacamole in front of the net-mgr report
# so the ssh / rdp / vnc badges become things you can click, instead of
# ssh:// URLs that depend on whatever handler the viewing machine happens
# to have registered.
#
# Run as root ON NAS3:
#
#     /usr/local/src/net-mgr/contrib/install-guacamole.sh
#     /usr/local/src/net-mgr/contrib/install-guacamole.sh --uninstall
#
# Re-runnable: every step checks before it acts, so a second run after a
# failure picks up where the first stopped rather than doubling anything.
#
# ---------------------------------------------------------------------------
# Why this is not a one-liner, in case it needs changing later:
#
#   * Guacamole is STILL a javax.servlet application as of 1.6.0 — its
#     web.xml declares web-app_2_5. Tomcat 10 moved to the jakarta.*
#     namespace, so the packaged tomcat10 on 24.04 CANNOT run this WAR; it
#     deploys and then 404s in a way that looks like a bad path. Tomcat 9 is
#     required, and is still published upstream (9.0.122 at time of writing)
#     even though 24.04 dropped the package. Hence the two-branch container
#     install below.
#
#   * guacd and the web application must be the SAME version — mixing them
#     is explicitly unsupported and fails on protocol instructions the older
#     side does not know. So rather than pinning a version here and hoping it
#     matches, this reads the version out of the guacd that apt actually
#     installed and fetches that WAR. Distro bumps guacd, this follows.
#
#   * Tomcat is bound to 127.0.0.1. Without that it listens on every
#     interface, and anyone on 223 could hit :8080 directly and skip the
#     Apache authentication entirely — the proxy would be decorative.
#
#   * The Apache block below carries its OWN AuthUserFile and a bare
#     `Require valid-user`. The existing /net-mgr block lets clients on the
#     private CIDRs through WITHOUT a password, which is fine for a
#     read-only report and emphatically not fine for a shell prompt. Do not
#     "simplify" this by merging the two.
# ---------------------------------------------------------------------------

set -euo pipefail

GUAC_HOME=/etc/guacamole
TOMCAT_TARBALL_VER=9.0.122          # only used when tomcat9 is not packaged
TOMCAT_OPT=/opt/tomcat9
APACHE_CONF=/etc/apache2/conf-available/guacamole.conf
HTPASSWD=/etc/apache2/guacamole.htpasswd
SECRET_DIR=/etc/net-mgr/secrets
SECRET=$SECRET_DIR/guacamole
DL=https://downloads.apache.org/guacamole
ARCHIVE=https://archive.apache.org/dist/guacamole

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '   \033[33m!! %s\033[0m\n' "$*"; }
die()  { printf '   \033[31m** %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root"

# --- uninstall --------------------------------------------------------------
if [ "${1:-}" = "--uninstall" ]; then
    say "removing guacamole"
    a2disconf guacamole 2>/dev/null || true
    rm -f "$APACHE_CONF" "$HTPASSWD"
    systemctl reload apache2 2>/dev/null || true
    systemctl disable --now guacd 2>/dev/null || true
    if systemctl list-unit-files 2>/dev/null | grep -q '^tomcat9\.service'; then
        systemctl disable --now tomcat9 2>/dev/null || true
    fi
    rm -rf "$TOMCAT_OPT" /etc/systemd/system/tomcat9.service
    systemctl daemon-reload
    info "left in place (delete by hand if you mean it): $GUAC_HOME, $SECRET,"
    info "and the guacd package itself — apt-get purge guacd"
    exit 0
fi

# --- 0. what are we on ------------------------------------------------------
say "host"
. /etc/os-release
info "$PRETTY_NAME  ($(uname -r))"
[ "$(hostname -s)" = nas3 ] || warn "hostname is $(hostname -s), not nas3 — continuing anyway"

command -v apache2ctl >/dev/null || die "apache2 not installed — this is meant for the box serving the net-mgr report"

# --- 1. guacd + protocol support -------------------------------------------
say "guacd and protocol libraries"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# The client libraries were renamed for the 64-bit time_t transition, so
# 24.04 has libguac-client-ssh0t64 where 22.04 has libguac-client-ssh0.
# Install whichever this archive actually has rather than guessing.
want=(guacd)
for proto in ssh rdp vnc telnet; do
    for cand in "libguac-client-${proto}0t64" "libguac-client-${proto}0"; do
        if apt-cache policy "$cand" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
            want+=("$cand"); break
        fi
    done
done
info "installing: ${want[*]}"
apt-get install -y -qq "${want[@]}" >/dev/null

# Read the version back out of what apt actually installed — this is what
# the WAR must match. Ask the binary first, fall back to the package version
# (the distro suffixes it, e.g. 1.3.0-1.3ubuntu1, so cut at the dash).
GUAC_VER=$(guacd -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
if [ -z "$GUAC_VER" ]; then
    GUAC_VER=$(dpkg-query -W -f='${Version}' guacd 2>/dev/null \
               | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)
fi
[ -n "$GUAC_VER" ] || die "cannot determine installed guacd version"
info "guacd $GUAC_VER — the WAR will be pinned to this"

systemctl enable --now guacd >/dev/null 2>&1 || true
systemctl is-active --quiet guacd || die "guacd did not start: journalctl -u guacd"
if command -v ss >/dev/null; then
    info "guacd listening on $(ss -ltnp 2>/dev/null | grep -m1 guacd | awk '{print $4}')"
fi

# --- 2. servlet container ---------------------------------------------------
say "servlet container (Tomcat 9 — Guacamole is still javax.servlet)"
if apt-cache policy tomcat9 2>/dev/null | grep -q 'Candidate: [0-9]'; then
    info "tomcat9 is packaged here — using it"
    apt-get install -y -qq tomcat9 >/dev/null
    CATALINA_BASE=/var/lib/tomcat9
    SERVER_XML=/etc/tomcat9/server.xml
    TOMCAT_UNIT=tomcat9
    TOMCAT_USER=tomcat
    DEFAULTS=/etc/default/tomcat9
else
    info "no tomcat9 package on $VERSION_ID — installing $TOMCAT_TARBALL_VER from apache.org"
    if [ ! -d "$TOMCAT_OPT" ]; then
        id -u tomcat >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$TOMCAT_OPT" tomcat
        tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
        base="https://downloads.apache.org/tomcat/tomcat-9/v${TOMCAT_TARBALL_VER}/bin"
        tgz="apache-tomcat-${TOMCAT_TARBALL_VER}.tar.gz"
        info "fetching $tgz"
        curl -sSfL --max-time 300 -o "$tmp/$tgz"      "$base/$tgz"
        curl -sSfL --max-time 60  -o "$tmp/$tgz.sha512" "$base/$tgz.sha512"
        ( cd "$tmp" && sha512sum -c "$tgz.sha512" >/dev/null ) \
            || die "tomcat tarball checksum mismatch — not unpacking it"
        info "checksum ok"
        mkdir -p "$TOMCAT_OPT"
        tar -xzf "$tmp/$tgz" -C "$TOMCAT_OPT" --strip-components=1
        chown -R tomcat: "$TOMCAT_OPT"
        rm -rf "$tmp"; trap - EXIT
    else
        info "$TOMCAT_OPT already present — leaving it"
    fi
    CATALINA_BASE=$TOMCAT_OPT
    SERVER_XML=$TOMCAT_OPT/conf/server.xml
    TOMCAT_UNIT=tomcat9
    TOMCAT_USER=tomcat
    DEFAULTS=

    if [ ! -f /etc/systemd/system/tomcat9.service ]; then
        JH=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")
        cat > /etc/systemd/system/tomcat9.service <<UNIT
[Unit]
Description=Apache Tomcat 9 (Guacamole)
After=network.target

[Service]
Type=forking
User=tomcat
Group=tomcat
Environment=JAVA_HOME=$JH
Environment=CATALINA_PID=$TOMCAT_OPT/temp/tomcat.pid
Environment=CATALINA_HOME=$TOMCAT_OPT
Environment=CATALINA_BASE=$TOMCAT_OPT
Environment=GUACAMOLE_HOME=$GUAC_HOME
ExecStart=$TOMCAT_OPT/bin/startup.sh
ExecStop=$TOMCAT_OPT/bin/shutdown.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        info "wrote /etc/systemd/system/tomcat9.service"
    fi
fi

# Bind to loopback only. Anything else makes the Apache auth optional,
# because :8080 would answer directly to the whole subnet.
if grep -q 'port="8080"' "$SERVER_XML" && ! grep -q 'address="127.0.0.1"' "$SERVER_XML"; then
    cp -n "$SERVER_XML" "$SERVER_XML.pre-guacamole"
    perl -0pi -e 's{(<Connector\s+port="8080")}{$1 address="127.0.0.1"}' "$SERVER_XML"
    info "bound the 8080 connector to 127.0.0.1 (backup: $SERVER_XML.pre-guacamole)"
else
    info "8080 connector already loopback-only, or not in the expected form — check $SERVER_XML"
fi

# The packaged unit reads GUACAMOLE_HOME from /etc/default/tomcat9.
if [ -n "$DEFAULTS" ] && ! grep -q GUACAMOLE_HOME "$DEFAULTS" 2>/dev/null; then
    echo "GUACAMOLE_HOME=$GUAC_HOME" >> "$DEFAULTS"
    info "added GUACAMOLE_HOME to $DEFAULTS"
fi

# --- 3. the web application -------------------------------------------------
say "guacamole $GUAC_VER web application"
WAR="$CATALINA_BASE/webapps/guacamole.war"
if [ ! -f "$WAR" ]; then
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    got=
    for root in "$DL" "$ARCHIVE"; do          # current releases, then archive
        url="$root/$GUAC_VER/binary/guacamole-$GUAC_VER.war"
        if curl -sSfL --max-time 300 -o "$tmp/g.war" "$url" 2>/dev/null; then
            got=$url
            curl -sSfL --max-time 60 -o "$tmp/g.war.sha256" "$url.sha256" 2>/dev/null || true
            break
        fi
    done
    [ -n "$got" ] || die "could not fetch guacamole-$GUAC_VER.war from either mirror"
    info "fetched $got"
    if [ -s "$tmp/g.war.sha256" ]; then
        exp=$(grep -oE '[0-9a-f]{64}' "$tmp/g.war.sha256" | head -1)
        act=$(sha256sum "$tmp/g.war" | cut -d' ' -f1)
        [ "$exp" = "$act" ] || die "WAR checksum mismatch (expected $exp, got $act)"
        info "checksum ok"
    else
        warn "no published .sha256 for this version — proceeding unverified"
    fi
    install -o "$TOMCAT_USER" -g "$TOMCAT_USER" -m 644 "$tmp/g.war" "$WAR"
    rm -rf "$tmp"; trap - EXIT
else
    info "$WAR already present"
fi

# --- 4. configuration -------------------------------------------------------
say "configuration"
mkdir -p "$GUAC_HOME/extensions" "$GUAC_HOME/lib"

cat > "$GUAC_HOME/guacamole.properties" <<PROPS
# Managed by net-mgr contrib/install-guacamole.sh
guacd-hostname: 127.0.0.1
guacd-port:     4822
user-mapping:   $GUAC_HOME/user-mapping.xml
PROPS
info "wrote $GUAC_HOME/guacamole.properties"

# quickconnect: lets you type ssh://host in the UI instead of needing a
# connection defined ahead of time for all ~239 hosts. net-mgr can generate
# real connection entries later; this makes the thing useful on day one.
QC="guacamole-auth-quickconnect-$GUAC_VER"
if [ ! -f "$GUAC_HOME/extensions/$QC.jar" ]; then
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    for root in "$DL" "$ARCHIVE"; do
        if curl -sSfL --max-time 180 -o "$tmp/qc.tgz" \
             "$root/$GUAC_VER/binary/$QC.tar.gz" 2>/dev/null; then
            tar -xzf "$tmp/qc.tgz" -C "$tmp"
            f=$(find "$tmp" -name "$QC.jar" | head -1)
            [ -n "$f" ] && install -m 644 "$f" "$GUAC_HOME/extensions/$QC.jar" \
                        && info "installed quickconnect extension"
            break
        fi
    done
    rm -rf "$tmp"; trap - EXIT
    [ -f "$GUAC_HOME/extensions/$QC.jar" ] || warn "quickconnect not available for $GUAC_VER — skipping"
else
    info "quickconnect already installed"
fi

# Guacamole's own login, behind Apache's. Password generated here, never
# committed, stored where the fleet keeps secrets.
mkdir -p "$SECRET_DIR"; chmod 700 "$SECRET_DIR"
if [ ! -f "$GUAC_HOME/user-mapping.xml" ]; then
    GPASS=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)
    # md5 rather than sha256: it is the encoding the file-auth provider has
    # supported in every release, and this file is 0600 root with Apache
    # basic-auth in front of it. Swap if you move to the database auth.
    GHASH=$(printf '%s' "$GPASS" | md5sum | cut -d' ' -f1)
    cat > "$GUAC_HOME/user-mapping.xml" <<MAP
<user-mapping>
    <!-- Managed by net-mgr contrib/install-guacamole.sh.
         Connections are not enumerated here: use the quickconnect box
         (ssh://host, rdp://host, vnc://host) or let net-mgr generate
         entries from the ports it already knows about. -->
    <authorize username="netmgr" password="$GHASH" encoding="md5">
    </authorize>
</user-mapping>
MAP
    chmod 600 "$GUAC_HOME/user-mapping.xml"
    printf 'guacamole web login\nuser: netmgr\npass: %s\n' "$GPASS" > "$SECRET"
    chmod 600 "$SECRET"
    info "created guacamole login 'netmgr' — password in $SECRET"
else
    info "$GUAC_HOME/user-mapping.xml exists — leaving credentials alone"
fi

# --- 5. apache front end ----------------------------------------------------
say "apache reverse proxy"
a2enmod proxy proxy_http proxy_wstunnel >/dev/null 2>&1 || \
    die "could not enable proxy modules — is this really the apache host?"

# htpasswd lives in apache2-utils, which is NOT pulled in by apache2 itself.
command -v htpasswd >/dev/null || apt-get install -y -qq apache2-utils >/dev/null

if [ ! -f "$HTPASSWD" ]; then
    APASS=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)
    htpasswd -bc "$HTPASSWD" netmgr "$APASS" >/dev/null 2>&1
    chown root:www-data "$HTPASSWD"; chmod 640 "$HTPASSWD"
    printf 'apache basic-auth in front of /guacamole\nuser: netmgr\npass: %s\n' "$APASS" >> "$SECRET"
    info "created apache basic-auth user 'netmgr' — password appended to $SECRET"
else
    info "$HTPASSWD exists — leaving it"
fi

cat > "$APACHE_CONF" <<'CONF'
# Managed by net-mgr contrib/install-guacamole.sh
#
# Deliberately NOT sharing the /net-mgr auth policy. That one lets private
# CIDRs through without a password because it fronts a read-only report.
# This fronts a shell prompt, so every request authenticates.
<Location /guacamole/>
    AuthType Basic
    AuthName "guacamole"
    AuthUserFile /etc/apache2/guacamole.htpasswd
    AuthBasicProvider file
    Require valid-user

    ProxyPass        http://127.0.0.1:8080/guacamole/ flushpackets=on
    ProxyPassReverse http://127.0.0.1:8080/guacamole/
</Location>

# The terminal itself rides a websocket; without this it silently falls back
# to HTTP polling and feels broken under any latency.
<Location /guacamole/websocket-tunnel>
    AuthType Basic
    AuthName "guacamole"
    AuthUserFile /etc/apache2/guacamole.htpasswd
    AuthBasicProvider file
    Require valid-user

    ProxyPass        ws://127.0.0.1:8080/guacamole/websocket-tunnel
    ProxyPassReverse ws://127.0.0.1:8080/guacamole/websocket-tunnel
</Location>
CONF
a2enconf guacamole >/dev/null 2>&1 || true
apache2ctl configtest 2>&1 | grep -qi 'syntax ok' || die "apache configtest failed — not reloading"
systemctl reload apache2
info "wrote $APACHE_CONF and reloaded apache"

# --- 6. start and prove -----------------------------------------------------
say "starting"
systemctl enable "$TOMCAT_UNIT" >/dev/null 2>&1 || true
systemctl restart "$TOMCAT_UNIT"

ok=
for i in $(seq 1 30); do
    sleep 2
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
           http://127.0.0.1:8080/guacamole/ 2>/dev/null || true)
    case "$code" in 200|302) ok=$code; break;; esac
    printf '   waiting for tomcat to deploy the war (%ss)\r' $((i*2))
done
echo
[ -n "$ok" ] || die "guacamole did not come up — journalctl -u $TOMCAT_UNIT, and check $CATALINA_BASE/logs/catalina.out"
info "tomcat serving /guacamole (HTTP $ok on 127.0.0.1:8080)"

front=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1/guacamole/ 2>/dev/null || true)
info "via apache without credentials: HTTP $front (401 is correct — it means auth is on)"

say "done"
cat <<DONE
   URL:         http://nas3/guacamole/
   credentials: $SECRET   (two logins: apache basic-auth, then guacamole)
   connect to a host by typing  ssh://lenny  (or rdp://, vnc://) in the UI

   guacd $GUAC_VER, tomcat on 127.0.0.1:8080 only, apache requires a password
   for every request including from 223.
DONE

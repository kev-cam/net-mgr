# net-mgr install layout.
#
# Default target ('list') prints the file list — no changes made.
# Run 'make install' to actually copy.
# Override paths on the command line, e.g.  make install PREFIX=/opt
#
# Path-substitution at install time rewrites each script's
#   use lib "$FindBin::Bin/../lib";
# (and the daemon's schema_dir = "$FindBin::Bin/../sql") to the absolute
# install paths so the binaries don't depend on FindBin resolving back
# to a source tree.

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SBINDIR    ?= $(PREFIX)/sbin
PERL5DIR   ?= $(PREFIX)/share/perl5
SHAREDIR   ?= $(PREFIX)/share/net-mgr
RECOVERYDIR?= $(PREFIX)/lib/net-mgr/recovery
MANDIR     ?= $(PREFIX)/share/man
SYSCONFDIR ?= /etc
UNITDIR    ?= $(SYSCONFDIR)/systemd/system
CGIDIR     ?= /usr/lib/cgi-bin
APACHE_CONF_DIR ?= $(SYSCONFDIR)/apache2/conf-available
DESTDIR    ?=

BINS  = net-add-public-dns net-alias net-bitchat-bridge net-bitchat-helper-wrap net-mgr-bitchat-setup net-chat net-chat-askpass net-chat-autoresponder net-poll-ap net-audit net-audit-aps net-cluster net-cluster-gui net-config-gui net-connect net-ddns net-dhcp-cycle net-diag net-discover net-find net-fw net-gen-apache-conf net-gen-dnsmasq net-import-dhcp net-import-dnsmasq net-import-ssh-forwards net-fix net-ipv6 net-isp net-link-stats net-lookup net-mac net-name net-peer net-ping net-purge net-vlan net-kill-rogue-dhcp net-reserve net-roam net-router net-run-app net-scan net-report net-set net-show net-tp-scan net-tunnel net-uplink-probe net-var net-watch net-wifi-survey net-zones

# Symlinks installed pointing at net-run-app — each link picks its
# behavior from basename($0) so adding a new wrapper is a one-line
# entry in net-run-app's %SPEC + a name here.
RUN_APP_LINKS = net-ssh net-mosh net-sftp net-scp net-rsync net-vnc

# Symlinks installed pointing at net-find — each historical script name
# maps to a sub-command inside net-find (basename dispatch). Kept for
# backward compat; net-find emits a soft-deprecation warning when
# invoked via one of these names.
FIND_LINKS    = net-find-lost net-find-peers net-find-rogue-dhcp
SBINS = net-mgr net-mgr-setup net-dns net-mgr-relay net-mgr-self-update net-mgr-deploy net-mgr-netif-hook net-mgr-reset-ble net-mgr-dnsmasq-switch
# Recovery scripts live off PATH so net-find can enumerate them
# without polluting BINDIR. Each script must support --describe.
RECOVERYS = net-recover-tlsg2424
UNITS = net-mgr.service net-dns.service net-mgr-relay.service net-bitchat-bridge.service net-chat-autoresponder.service
MAN1S = net-alias.1 net-chat.1 net-connect.1 net-diag.1 net-discover.1 net-fix.1 \
        net-gen-dnsmasq.1 net-import-dhcp.1 net-import-dnsmasq.1 \
        net-import-ssh-forwards.1 net-name.1 net-ping.1 \
        net-poll-ap.1 net-report.1 net-reserve.1 net-roam.1 net-router.1 net-scan.1 \
        net-show.1 net-tp-scan.1 net-var.1 net-watch.1
MAN7S = net-mgr.7
LIBS  = NetMgr/Where.pm NetMgr/Protocol.pm NetMgr/Addr.pm NetMgr/Vlan.pm NetMgr/Tunnel.pm NetMgr/Ddns.pm NetMgr/Secret.pm NetMgr/HE.pm NetMgr/Config.pm NetMgr/DB.pm \
        NetMgr/Manager.pm NetMgr/Client.pm NetMgr/Multi.pm NetMgr/Mesh.pm \
        NetMgr/Election.pm NetMgr/AutoDiscover.pm NetMgr/Resolver.pm \
        NetMgr/Relay.pm NetMgr/Vendor.pm NetMgr/Subnets.pm \
        NetMgr/HostDebug.pm NetMgr/Auth.pm NetMgr/ChatArchive.pm NetMgr/Caps.pm \
        NetMgr/Producer/AP.pm NetMgr/Producer/Scan.pm \
        NetMgr/Producer/DhcpMaster.pm NetMgr/Producer/Fingerprint.pm

INSTALL ?= install

.PHONY: list install install-on deploy pod-image setup deps uninstall test check clean help .version

# --- dependency check (Debian/Ubuntu apt names) ----------------------
# Required deps must be present; optional deps print a hint but don't
# fail the install (e.g. Net::DNS only matters for sbin/net-dns).
#
# A client-only install (e.g. on Cygwin, where you only want the
# NetMgr::Client lib for find-xpra) doesn't need the server-side deps
# (MariaDB, DBI, DBD::mysql, fping, ip, ...).  Set FORCE=1 to skip the
# prompt; on a tty `make install` will offer to continue anyway.
FORCE ?=

define DEPS_CHECK_SH
miss=""; opt_miss=""; \
check() { \
  if /bin/sh -c "$$1" >/dev/null 2>&1; then \
    printf "  ok       %-20s %s\n" "$$2" "$$3"; \
  else \
    printf "  MISSING  %-20s %s\n" "$$2" "$$3"; \
    miss="$$miss $$2"; \
  fi; \
}; \
check_opt() { \
  if /bin/sh -c "$$1" >/dev/null 2>&1; then \
    printf "  ok       %-20s %s (optional)\n" "$$2" "$$3"; \
  else \
    printf "  optional %-20s %s\n" "$$2" "$$3"; \
    opt_miss="$$opt_miss $$2"; \
  fi; \
}; \
check 'command -v nmap'           nmap              'nmap (discovery sweep)'; \
check 'command -v fping'          fping             'fping (presence check)'; \
check 'command -v ssh'            openssh-client    'ssh client (AP polling)'; \
check 'command -v ip'             iproute2          'ip command (auto-detect networks)'; \
check 'command -v mysql'          mariadb-client    'mysql client (setup script)'; \
check '/usr/bin/perl -MDBI -e 1'        libdbi-perl       'Perl DBI'; \
check '/usr/bin/perl -MDBD::mysql -e 1' libdbd-mysql-perl 'Perl DBD::mysql'; \
check '{ dpkg -l mariadb-server 2>/dev/null | grep -q "^ii "; } \
    || { dpkg -l mysql-server 2>/dev/null | grep -q "^ii "; } \
    || { dpkg -l mysql-server-8.0 2>/dev/null | grep -q "^ii "; } \
    || { dpkg -l mysql-server-8.4 2>/dev/null | grep -q "^ii "; }' \
                                  mariadb-server    'MariaDB or MySQL server (either is fine)'; \
check_opt '/usr/bin/perl -MNet::DNS -e 1' libnet-dns-perl 'Net::DNS — only needed if you run sbin/net-dns'; \
miss=$$(echo $$miss | tr ' ' '\n' | sort -u | tr '\n' ' '); \
miss=$${miss% }; miss=$${miss# }; \
opt_miss=$$(echo $$opt_miss | tr ' ' '\n' | sort -u | tr '\n' ' '); \
opt_miss=$${opt_miss% }; opt_miss=$${opt_miss# }
endef

deps:
	@$(DEPS_CHECK_SH); \
	if [ -n "$$miss" ]; then \
	  echo; \
	  echo "install missing required packages with:"; \
	  echo "  sudo apt install -y $$miss"; \
	  exit 1; \
	fi; \
	echo; \
	echo "all required dependencies present"; \
	if [ -n "$$opt_miss" ]; then \
	  echo "(optional, install if you want net-dns):"; \
	  echo "  sudo apt install -y $$opt_miss"; \
	fi

# --- default: dry-run listing ----------------------------------------
list:
	@echo "net-mgr install plan (no changes — run 'make install' to do it)"
	@echo
	@echo "binaries → $(DESTDIR)$(BINDIR):"
	@for f in $(BINS); do echo "  $$f"; done
	@echo
	@echo "daemon → $(DESTDIR)$(SBINDIR):"
	@for f in $(SBINS); do echo "  $$f"; done
	@echo
	@echo "recovery scripts (off PATH) → $(DESTDIR)$(RECOVERYDIR):"
	@for f in $(RECOVERYS); do echo "  $$f"; done
	@echo
	@echo "perl modules → $(DESTDIR)$(PERL5DIR):"
	@for f in $(LIBS); do echo "  $$f"; done
	@echo
	@echo "sql + sample config:"
	@echo "  $(DESTDIR)$(SHAREDIR)/sql/schema.sql"
	@echo "  $(DESTDIR)$(SYSCONFDIR)/net-mgr/config  (only if not already present)"
	@echo "  (legacy $(DESTDIR)$(SYSCONFDIR)/net-mgr.conf gets moved automatically)"
	@echo
	@echo "man pages → $(DESTDIR)$(MANDIR)/man1, man7:"
	@for f in $(MAN1S) $(MAN7S); do echo "  $$f"; done
	@echo
	@echo "systemd units → $(DESTDIR)$(UNITDIR):"
	@for f in $(UNITS); do echo "  $$f"; done
	@echo
	@echo "scripts will have their 'use lib' rewritten to:"
	@echo "  $(PERL5DIR)"
	@echo
	@echo "first-time DB bootstrap (auto-invoked from 'install' when root):"
	@echo "  creates MySQL database 'netmgr' and writes /etc/net-mgr/root.conf [net-mgr] section"
	@echo "  (run 'make setup' standalone to do just this step)"
	@echo
	@echo "vars: PREFIX=$(PREFIX)  DESTDIR=$(DESTDIR)  SYSCONFDIR=$(SYSCONFDIR)"
	@echo
	@echo "remote install: make install-on TARGET=host [SUDO=sudo] [SSHOPTS=..] [MAKEARGS='FORCE=1'] [KEEP=1]"
	@echo "  rsyncs this tree to /tmp/$$USER/net-mgr on the target,"
	@echo "  runs 'make install' there, then removes the tmp dir."
	@echo "fleet deploy:   make deploy   (installs on every host in [deploy] of $(DEPLOY_CONF))"
	@echo "  configure once: [deploy] hosts = nas3, bigsony, workhorse(FORCE=1,CYGWIN=1)"
	@echo "    per-host make args go in (..) and override the default make_args; sudo/ssh_opts optional"
	@echo
	@echo "--- dependency check ---"
	@$(MAKE) -s deps || true

# --- install ----------------------------------------------------------
# .version is regenerated from git on every invocation when run from a
# git checkout; on a host without .git/ (e.g. after install-on rsync'd
# us into /tmp) we leave whatever .version was rsync'd in place. The
# install banner reads from this file rather than calling git directly,
# so remote installs see the source tree's version, not '(no git)'.
#
# When 'sudo make install' is run on a build dir owned by a regular
# user, recent git refuses to operate ('detected dubious ownership in
# repository'). Drop to the build dir's owner via su for the git
# queries, then chown .version back so the user can rewrite it on the
# next build.
.version:
	@if [ -d .git ] && command -v git >/dev/null 2>&1; then \
	  OWNER=$$(stat -c %U .git); \
	  if [ "$$(id -un)" = "root" ] && [ "$$OWNER" != "root" ]; then \
	    AS="su -s /bin/sh $$OWNER -c"; \
	  else \
	    AS="sh -c"; \
	  fi; \
	  V=$$($$AS "git -C '$(CURDIR)' describe --tags --always --dirty" 2>/dev/null \
	       || $$AS "git -C '$(CURDIR)' rev-parse --short HEAD" 2>/dev/null \
	       || echo unknown); \
	  D=$$($$AS "git -C '$(CURDIR)' log -1 --format=%cd --date=format:%Y-%m-%d\ %H:%M" 2>/dev/null); \
	  printf '%s%s\n' "$$V" "$${D:+ ($$D)}" > .version; \
	  if [ "$$(id -un)" = "root" ] && [ "$$OWNER" != "root" ]; then \
	    chown "$$OWNER" .version 2>/dev/null || true; \
	  fi; \
	elif [ ! -f .version ]; then \
	  echo 'unknown' > .version; \
	fi

install: .version
	@printf '==> Installing net-mgr %s on %s from %s\n' \
	    "$$(cat .version)" \
	    "$$(hostname)" \
	    "$(CURDIR)"
	@$(DEPS_CHECK_SH); \
	if [ -n "$$miss" ]; then \
	  echo; echo "Missing required: $$miss"; \
	  echo "Install on Debian/Ubuntu:  sudo apt install -y $$miss"; \
	  if [ "$(FORCE)" = "1" ]; then \
	    echo "(FORCE=1: continuing despite missing dependencies)"; \
	  elif [ -t 0 ]; then \
	    printf "Continue install anyway? [y/N] "; \
	    read ans; \
	    case "$$ans" in [yY]*) ;; *) echo "Aborted."; exit 1 ;; esac; \
	  else \
	    echo "(non-interactive: aborting; rerun with FORCE=1 to override)" >&2; \
	    exit 1; \
	  fi; \
	fi
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(RECOVERYDIR)
	$(INSTALL) -d $(DESTDIR)$(PERL5DIR)/NetMgr/Producer
	$(INSTALL) -d $(DESTDIR)$(SHAREDIR)/sql
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/net-mgr
	$(INSTALL) -d $(DESTDIR)$(UNITDIR)
	@VERSION="$$(cat .version)"; \
	 for f in $(BINS); do \
	  echo "  bin/$$f → $(DESTDIR)$(BINDIR)/$$f"; \
	  sed -e 's|use lib .*FindBin.*|use lib "$(PERL5DIR)";|' \
	      -e 's|"\$$FindBin::Bin/../recovery"|"$(RECOVERYDIR)"|' \
	      -e "s|@NET_MGR_VERSION@|$$VERSION|g" \
	      bin/$$f > $(DESTDIR)$(BINDIR)/$$f.tmp && \
	  mv $(DESTDIR)$(BINDIR)/$$f.tmp $(DESTDIR)$(BINDIR)/$$f && \
	  chmod 755 $(DESTDIR)$(BINDIR)/$$f; \
	done
	@for l in $(RUN_APP_LINKS); do \
	  echo "  symlink $(DESTDIR)$(BINDIR)/$$l → net-run-app"; \
	  ln -sf net-run-app $(DESTDIR)$(BINDIR)/$$l; \
	done
	@for l in $(FIND_LINKS); do \
	  echo "  symlink $(DESTDIR)$(BINDIR)/$$l → net-find"; \
	  ln -sf net-find $(DESTDIR)$(BINDIR)/$$l; \
	done
	@for f in $(RECOVERYS); do \
	  echo "  recovery/$$f → $(DESTDIR)$(RECOVERYDIR)/$$f"; \
	  $(INSTALL) -m 755 recovery/$$f $(DESTDIR)$(RECOVERYDIR)/$$f; \
	done
	@for f in $(SBINS); do \
	  echo "  sbin/$$f → $(DESTDIR)$(SBINDIR)/$$f"; \
	  sed -e 's|use lib .*FindBin.*|use lib "$(PERL5DIR)";|' \
	      -e 's|"\$$FindBin::Bin/../sql"|"$(SHAREDIR)/sql"|' \
	      sbin/$$f > $(DESTDIR)$(SBINDIR)/$$f.tmp && \
	  mv $(DESTDIR)$(SBINDIR)/$$f.tmp $(DESTDIR)$(SBINDIR)/$$f && \
	  chmod 755 $(DESTDIR)$(SBINDIR)/$$f; \
	done
	@for f in $(LIBS); do \
	  echo "  lib/$$f → $(DESTDIR)$(PERL5DIR)/$$f"; \
	  $(INSTALL) -m 644 lib/$$f $(DESTDIR)$(PERL5DIR)/$$f; \
	done
	@echo "  sql/schema.sql → $(DESTDIR)$(SHAREDIR)/sql/schema.sql"
	@$(INSTALL) -m 644 sql/schema.sql $(DESTDIR)$(SHAREDIR)/sql/schema.sql
	@echo "  .version → $(DESTDIR)$(SHAREDIR)/version"
	@$(INSTALL) -m 644 .version $(DESTDIR)$(SHAREDIR)/version
	@if [ -f contrib/bitchat-jsonl/bitchat-jsonl.rs ]; then \
	  echo "  contrib/bitchat-jsonl/bitchat-jsonl.rs → $(DESTDIR)$(SHAREDIR)/bitchat-jsonl.rs"; \
	  $(INSTALL) -m 644 contrib/bitchat-jsonl/bitchat-jsonl.rs \
	             $(DESTDIR)$(SHAREDIR)/bitchat-jsonl.rs; \
	fi
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man7
	@for f in $(MAN1S); do \
	  echo "  man/$$f → $(DESTDIR)$(MANDIR)/man1/$$f"; \
	  $(INSTALL) -m 644 man/$$f $(DESTDIR)$(MANDIR)/man1/$$f; \
	done
	@for f in $(MAN7S); do \
	  echo "  man/$$f → $(DESTDIR)$(MANDIR)/man7/$$f"; \
	  $(INSTALL) -m 644 man/$$f $(DESTDIR)$(MANDIR)/man7/$$f; \
	done
	@for f in $(UNITS); do \
	  echo "  systemd/$$f → $(DESTDIR)$(UNITDIR)/$$f"; \
	  $(INSTALL) -m 644 systemd/$$f $(DESTDIR)$(UNITDIR)/$$f; \
	done
	@if [ -d $(DESTDIR)$(APACHE_CONF_DIR) ]; then \
	  $(INSTALL) -d $(DESTDIR)$(CGIDIR); \
	  echo "  web/net-mgr-web.cgi → $(DESTDIR)$(CGIDIR)/net-mgr-web.cgi"; \
	  $(INSTALL) -m 755 web/net-mgr-web.cgi $(DESTDIR)$(CGIDIR)/net-mgr-web.cgi; \
	  echo "  web/net-mgr.conf → $(DESTDIR)$(APACHE_CONF_DIR)/net-mgr.conf"; \
	  $(INSTALL) -m 644 web/net-mgr.conf $(DESTDIR)$(APACHE_CONF_DIR)/net-mgr.conf; \
	  echo "  (run: a2enmod cgid && a2enconf net-mgr && systemctl restart apache2)"; \
	else \
	  echo "  skip web/* (no apache at $(APACHE_CONF_DIR))"; \
	fi
	@if [ -f $(DESTDIR)$(SYSCONFDIR)/net-mgr.conf ] \
	     && [ ! -e $(DESTDIR)$(SYSCONFDIR)/net-mgr/config ]; then \
	  echo "  migrating $(DESTDIR)$(SYSCONFDIR)/net-mgr.conf → $(DESTDIR)$(SYSCONFDIR)/net-mgr/config"; \
	  mv $(DESTDIR)$(SYSCONFDIR)/net-mgr.conf $(DESTDIR)$(SYSCONFDIR)/net-mgr/config; \
	fi
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/net-mgr/config ]; then \
	  echo "  etc/config.sample → $(DESTDIR)$(SYSCONFDIR)/net-mgr/config"; \
	  $(INSTALL) -m 644 etc/config.sample \
	             $(DESTDIR)$(SYSCONFDIR)/net-mgr/config; \
	else \
	  echo "  skip $(DESTDIR)$(SYSCONFDIR)/net-mgr/config (already exists)"; \
	fi
	@if [ -f etc/bitchat-bridge.conf.sample ] \
	     && [ ! -f $(DESTDIR)$(SYSCONFDIR)/net-mgr/bitchat-bridge.conf ]; then \
	  echo "  etc/bitchat-bridge.conf.sample → $(DESTDIR)$(SYSCONFDIR)/net-mgr/bitchat-bridge.conf"; \
	  $(INSTALL) -m 644 etc/bitchat-bridge.conf.sample \
	             $(DESTDIR)$(SYSCONFDIR)/net-mgr/bitchat-bridge.conf; \
	fi
	@if [ -f etc/net-chat-autoresponder.conf.sample ] \
	     && [ ! -f $(DESTDIR)$(SYSCONFDIR)/net-mgr/net-chat-autoresponder.conf ]; then \
	  echo "  etc/net-chat-autoresponder.conf.sample → $(DESTDIR)$(SYSCONFDIR)/net-mgr/net-chat-autoresponder.conf"; \
	  $(INSTALL) -m 644 etc/net-chat-autoresponder.conf.sample \
	             $(DESTDIR)$(SYSCONFDIR)/net-mgr/net-chat-autoresponder.conf; \
	fi
	@$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/net-mgr/net-chat-autoresponder.d
	@if [ -f etc/shared-wifi.conf.sample ] \
	     && [ ! -f $(DESTDIR)$(SYSCONFDIR)/net-mgr/shared-wifi.conf ]; then \
	  echo "  etc/shared-wifi.conf.sample → $(DESTDIR)$(SYSCONFDIR)/net-mgr/shared-wifi.conf"; \
	  $(INSTALL) -m 644 etc/shared-wifi.conf.sample \
	             $(DESTDIR)$(SYSCONFDIR)/net-mgr/shared-wifi.conf; \
	fi
	@$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/net-mgr/shared-wifi.d
	@CFG=$(DESTDIR)$(SYSCONFDIR)/net-mgr/config; \
	  perl -Ilib -MNetMgr::Config -e 'my @d = NetMgr::Config::dead_keys($$ARGV[0]); exit unless @d; print STDERR "\nWARN: $$ARGV[0] has keys no longer read by the daemon:\n"; print STDERR "  $$_\n" for @d; print STDERR "(harmless, but you can delete them.)\n"' "$$CFG"
	@echo
	@echo "Files installed."
	@if [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = "0" ]; then \
	  need_setup=0; \
	  if ! grep -q '^\[net-mgr\]' /etc/net-mgr/root.conf 2>/dev/null && ! grep -q '^\[net-mgr\]' /root/.my.cnf 2>/dev/null; then \
	    need_setup=1; \
	  fi; \
	  if [ $$need_setup = 1 ]; then \
	    if [ -t 0 ] && [ -t 1 ]; then \
	      echo; echo "Running first-time DB setup..."; \
	      if ! $(DESTDIR)$(SBINDIR)/net-mgr-setup; then \
	        echo; \
	        echo "*** net-mgr-setup did NOT complete. /etc/net-mgr/root.conf was not written."; \
	        echo "*** The daemon will fail to start until you re-run it:"; \
	        echo "***   sudo $(SBINDIR)/net-mgr-setup"; \
	      elif ! grep -q '^\[net-mgr\]' /etc/net-mgr/root.conf 2>/dev/null && ! grep -q '^\[net-mgr\]' /root/.my.cnf 2>/dev/null; then \
	        echo; \
	        echo "*** net-mgr-setup exited 0 but no [net-mgr] section in /etc/net-mgr/root.conf (or /root/.my.cnf)."; \
	        echo "*** Re-run it before starting the daemon:"; \
	        echo "***   sudo $(SBINDIR)/net-mgr-setup"; \
	      fi; \
	    else \
	      echo; \
	      echo "*** No TTY for interactive setup. /etc/net-mgr/root.conf is missing or"; \
	      echo "*** has no [net-mgr] section, so the daemon will fail to start."; \
	      echo "*** Run setup manually before starting the service:"; \
	      echo "***   sudo $(SBINDIR)/net-mgr-setup"; \
	    fi; \
	  else \
	    echo "(credentials present in /etc/net-mgr/root.conf or /root/.my.cnf — skipping setup)"; \
	  fi; \
	  if command -v systemctl >/dev/null 2>&1; then \
	    echo; \
	    systemctl daemon-reload; \
	    for u in $(UNITS); do \
	      if systemctl is-active --quiet "$$u"; then \
	        printf '  %-25s restarting (was running with previous binaries)\n' "$$u"; \
	        systemctl restart "$$u" \
	          || printf '  *** restart %s failed; check: systemctl status %s\n' "$$u" "$$u"; \
	      elif systemctl is-enabled --quiet "$$u" 2>/dev/null; then \
	        printf '  %-25s enabled but stopped — starting\n' "$$u"; \
	        systemctl start "$$u" \
	          || printf '  *** start %s failed; check: systemctl status %s\n' "$$u" "$$u"; \
	      elif [ "$$u" = "net-bitchat-bridge.service" ]; then \
	        printf '  %-25s default-on — enabling + starting\n' "$$u"; \
	        systemctl enable --now "$$u" \
	          || printf '  *** enable %s failed; ExecCondition will skip cleanly if BT/helper absent\n' "$$u"; \
	      else \
	        printf '  %-25s not enabled  — enable with: systemctl enable --now %s\n' "$$u" "$$u"; \
	      fi; \
	    done; \
	  fi; \
	  if ! command -v bitchat-jsonl >/dev/null 2>&1 && \
	     ! ls /home/*/src/bitchat-rust/target/release/bitchat-jsonl 2>/dev/null | grep -q .; then \
	    echo; \
	    echo "  Note: BitChat support requires a Rust helper that net-mgr does not"; \
	    echo "        ship pre-built. net-bitchat-bridge.service is enabled but its"; \
	    echo "        ExecCondition will keep it skipped (see journalctl) until the"; \
	    echo "        helper is built. To enable BitChat on this host, run AS YOUR"; \
	    echo "        LOGIN USER (not root — toolchain installs under ~/.cargo/):"; \
	    echo "          $(BINDIR)/net-mgr-bitchat-setup"; \
	    echo "        Then: sudo systemctl restart net-bitchat-bridge"; \
	  fi; \
	else \
	  echo; \
	  echo "Next: sudo make setup           (or: sudo $(SBINDIR)/net-mgr-setup)"; \
	  echo "Then: sudo systemctl enable --now net-mgr.service"; \
	fi

# --- install on a remote host via rsync + ssh ------------------------
# Examples:
#   make install-on TARGET=gateway3
#   make install-on TARGET=root@gateway3 KEEP=1
#   make install-on TARGET=gateway3 SUDO=sudo
#   make install-on TARGET=gateway3 SSHOPTS='-p 2222 -i ~/.ssh/firewall'
#   make install-on TARGET=gateway3 MAKEARGS='FORCE=1'
#
# Variables:
#   TARGET    [required] ssh-style target (host or user@host)
#   SSHOPTS   extra args passed to ssh and rsync (e.g. '-p 2222')
#   SUDO      command to prefix the remote 'make install' with
#             (e.g. SUDO=sudo for hosts where you don't ssh as root)
#   KEEP      set to 1 to leave /tmp/<user>/net-mgr in place
#   MAKEARGS  extra args appended to the remote 'make install'
REMOTE_TMP ?= /tmp/$(USER)/net-mgr
SUDO       ?=
SSHOPTS    ?=
# Config file `make deploy` reads its [deploy] hosts from.
DEPLOY_CONF ?= $(if $(NET_MGR_CONF),$(NET_MGR_CONF),/etc/net-mgr/config)
MAKEARGS   ?=

install-on: .version
	@if [ -z "$(TARGET)" ]; then \
	  echo "Usage: make install-on TARGET=host  [KEEP=1] [SUDO=sudo] [SSHOPTS='-p 2222'] [MAKEARGS='FORCE=1']"; \
	  exit 2; \
	fi
	@# When SUDO=sudo, force a remote TTY so sudo can prompt for a
	@# password from the user's terminal; rsync still uses the bare
	@# SSHOPTS so it doesn't get confused by the -t.
	$(eval RUNOPTS := $(if $(SUDO),-t $(SSHOPTS),$(SSHOPTS)))
	@echo "==> $(TARGET): preparing $(REMOTE_TMP)"
	@ssh $(SSHOPTS) $(TARGET) "mkdir -p $(REMOTE_TMP)"
	@echo "==> $(TARGET): rsync working tree"
	@rsync -az --delete \
	  --exclude='.git/' --exclude='*.swp' --exclude='*~' \
	  --exclude='/tmp' --exclude='blib/' \
	  -e "ssh $(SSHOPTS)" \
	  ./ $(TARGET):$(REMOTE_TMP)/
	@# Per-host config overlay: if /etc/net-mgr/deploy/<target>/ exists on
	@# THIS (deploying) host, rsync its contents under /etc/net-mgr/ on
	@# the target BEFORE the install runs. Lets the deployer (e.g. nas3)
	@# own a leaf node's net-mgr config without giving the leaf its own
	@# allowed_updaters/write_config trust. The overlay path is fixed —
	@# files under /etc/net-mgr/deploy/<host>/X.conf land at /etc/net-mgr/X.conf.
	@# Skipped silently when the overlay dir doesn't exist (normal case).
	@overlay=/etc/net-mgr/deploy/$(TARGET); \
	if [ -d "$$overlay" ]; then \
	  echo "==> $(TARGET): overlay $$overlay -> /etc/net-mgr/"; \
	  rsync -az -e "ssh $(SSHOPTS)" --rsync-path="$(SUDO) rsync" \
	    "$$overlay/" $(TARGET):/etc/net-mgr/ \
	    || echo "  *** overlay rsync failed (continuing)"; \
	fi
	@echo "==> $(TARGET): $(SUDO) make -C $(REMOTE_TMP) install $(MAKEARGS)"
	@ssh $(RUNOPTS) $(TARGET) "$(SUDO) make -C $(REMOTE_TMP) install $(MAKEARGS)"
	@if [ "$(KEEP)" = "1" ]; then \
	  echo "==> $(TARGET): leaving $(REMOTE_TMP) in place (KEEP=1)"; \
	else \
	  echo "==> $(TARGET): cleaning up $(REMOTE_TMP)"; \
	  ssh $(SSHOPTS) $(TARGET) "rm -rf $(REMOTE_TMP)"; \
	fi
	@echo "==> $(TARGET): install-on done"

# --- deploy to the whole fleet from [deploy] in the config -----------
#   make deploy                         # uses [deploy] hosts in $(DEPLOY_CONF)
#   make deploy DEPLOY_CONF=./my.conf   # a different config file
# Reads hosts/sudo/ssh_opts/make_args from the [deploy] section and runs
# install-on for each host. Edit the config once; deploy with one command.
deploy: .version
	@command -v perl >/dev/null 2>&1 || { echo "perl required for 'make deploy'"; exit 1; }
	@cfg='$(DEPLOY_CONF)'; \
	[ -f "$$cfg" ] || { echo "config '$$cfg' not found (set DEPLOY_CONF=)"; exit 2; }; \
	get() { perl -Ilib -MNetMgr::Config -e \
	  'my $$c=NetMgr::Config->load($$ARGV[0]); my $$v=$$c->{deploy}{$$ARGV[1]}//q(); $$v=~s/^\s+|\s+$$//g; print $$v' \
	  "$$cfg" "$$1"; }; \
	entries=`perl -Ilib -MNetMgr::Config -e \
	  'my $$c=NetMgr::Config->load($$ARGV[0]); my $$h=$$c->{deploy}{hosts}//q(); while($$h=~/([^,()]+(?:\([^)]*\))?)/g){ my $$e=$$1; $$e=~s/\s+//g; print "$$e\n" if length $$e }' \
	  "$$cfg"`; \
	if [ -z "$$entries" ]; then \
	  echo "No [deploy] hosts in $$cfg. Add e.g.:"; \
	  echo "  [deploy]"; echo "  hosts = nas3, bigsony, workhorse(FORCE=1,CYGWIN=1)"; echo "  sudo  = sudo   # optional"; \
	  exit 2; \
	fi; \
	sudo_v=`get sudo`; sshopts_v=`get ssh_opts`; makeargs_v=`get make_args`; \
	echo "==> deploy (sudo='$$sudo_v' ssh='$$sshopts_v' default make_args='$$makeargs_v'; per-host (..) overrides)"; \
	failed=''; \
	for entry in $$entries; do \
	  h="$${entry%%(*}"; \
	  case "$$entry" in \
	    *\(*\)) a="$${entry#*(}"; a="$${a%)}"; margs=`echo "$$a" | tr ',' ' '`;; \
	    *)      margs="$$makeargs_v";; \
	  esac; \
	  echo; echo "===== $$h (make_args='$$margs') ====="; \
	  $(MAKE) --no-print-directory install-on TARGET="$$h" \
	      SUDO="$$sudo_v" SSHOPTS="$$sshopts_v" MAKEARGS="$$margs" \
	    || { echo "deploy: $$h FAILED — continuing"; failed="$$failed $$h"; }; \
	done; \
	if [ -n "$$failed" ]; then \
	  echo; echo "==> deploy finished with FAILURES:$$failed"; exit 1; \
	fi; \
	echo; echo "==> deploy complete"

# --- xpra-pod net-mgr image -----------------------------------------
#   make pod-image                       # build for the host's flavor
#   make pod-image POD_FLAVOR=ubuntu-noble
# Builds xpra-pod:<flavor>+net-mgr: the generic xpra-pod base (built first if
# absent) plus the net-mgr client tools, Perl/Tk, and tmux (see pod/Containerfile).
# Run a pod whose app shows through Xpra with:
#   xpra-pod run nc --flavor <flavor>+net-mgr -c 'net-chat --gui --server <srv>'
pod-image:
	@command -v podman >/dev/null 2>&1 || { echo "podman required for pod-image"; exit 1; }
	@command -v xpra-pod-build >/dev/null 2>&1 \
	  || { echo "xpra-pod-build not found (install the xpra-pod toolset)"; exit 1; }
	@flavor='$(POD_FLAVOR)'; \
	[ -n "$$flavor" ] \
	  || flavor=`xpra-pod-build --help 2>&1 | sed -n 's/^Detected flavor on this host: //p'`; \
	[ -n "$$flavor" ] \
	  || { echo "couldn't detect flavor; pass POD_FLAVOR= (xpra-pod-build --list)"; exit 2; }; \
	podman image exists "xpra-pod:$$flavor" || xpra-pod-build --flavor "$$flavor"; \
	echo "==> building xpra-pod:$$flavor+net-mgr"; \
	podman build -t "xpra-pod:$$flavor+net-mgr" --build-arg FLAVOR="$$flavor" \
	    -f pod/Containerfile . || exit 1; \
	echo; echo "==> built xpra-pod:$$flavor+net-mgr. Launch (app shows via Xpra):"; \
	echo "    xpra-pod run nc --flavor $$flavor+net-mgr -c 'net-chat --gui --server <srv>'"

# --- setup (interactive DB + creds bootstrap) ------------------------
setup:
	@if [ "$$(id -u)" != "0" ]; then \
	  echo "setup must run as root (it writes /etc/net-mgr/root.conf)"; exit 1; \
	fi
	$(DESTDIR)$(SBINDIR)/net-mgr-setup

# --- uninstall (does not remove /etc/net-mgr/ or /root/.my.cnf) ---
uninstall:
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	  for u in $(UNITS); do \
	    systemctl disable --now "$$u" 2>/dev/null || true; \
	  done; \
	fi
	@for f in $(BINS);      do rm -fv $(DESTDIR)$(BINDIR)/$$f;      done
	@for f in $(SBINS);     do rm -fv $(DESTDIR)$(SBINDIR)/$$f;     done
	@for f in $(RECOVERYS); do rm -fv $(DESTDIR)$(RECOVERYDIR)/$$f; done
	-@rmdir $(DESTDIR)$(RECOVERYDIR) 2>/dev/null || true
	-@rmdir $(DESTDIR)$(PREFIX)/lib/net-mgr 2>/dev/null || true
	@for f in $(LIBS);  do rm -fv $(DESTDIR)$(PERL5DIR)/$$f; done
	@for f in $(UNITS); do rm -fv $(DESTDIR)$(UNITDIR)/$$f; done
	@for f in $(MAN1S); do rm -fv $(DESTDIR)$(MANDIR)/man1/$$f; done
	@for f in $(MAN7S); do rm -fv $(DESTDIR)$(MANDIR)/man7/$$f; done
	@rm -fv $(DESTDIR)$(CGIDIR)/net-mgr-web.cgi 2>/dev/null || true
	@rm -fv $(DESTDIR)$(APACHE_CONF_DIR)/net-mgr.conf 2>/dev/null || true
	@rm -fv $(DESTDIR)$(SHAREDIR)/sql/schema.sql
	@rm -fv $(DESTDIR)$(SHAREDIR)/version
	-@rmdir $(DESTDIR)$(PERL5DIR)/NetMgr/Producer 2>/dev/null || true
	-@rmdir $(DESTDIR)$(PERL5DIR)/NetMgr          2>/dev/null || true
	-@rmdir $(DESTDIR)$(SHAREDIR)/sql             2>/dev/null || true
	-@rmdir $(DESTDIR)$(SHAREDIR)                 2>/dev/null || true
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	  systemctl daemon-reload; \
	fi
	@echo
	@echo "Kept: $(DESTDIR)$(SYSCONFDIR)/net-mgr/ (remove manually if desired)"

# --- tests / lint ----------------------------------------------------
test:
	prove -Ilib t/

check:
	@for f in $(LIBS);      do perl -Ilib -c lib/$$f      || exit 1; done
	@for f in $(BINS);      do perl -Ilib -c bin/$$f      || exit 1; done
	@for f in $(SBINS);     do perl -Ilib -c sbin/$$f     || exit 1; done
	@for f in $(RECOVERYS); do perl -Ilib -c recovery/$$f || exit 1; done
	@echo "compile: ok"

clean:
	@rm -f .version

help: list

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
MANDIR     ?= $(PREFIX)/share/man
SYSCONFDIR ?= /etc
UNITDIR    ?= $(SYSCONFDIR)/systemd/system
CGIDIR     ?= /usr/lib/cgi-bin
APACHE_CONF_DIR ?= $(SYSCONFDIR)/apache2/conf-available
DESTDIR    ?=

BINS  = net-alias net-poll-ap net-discover net-gen-dnsmasq net-import-dhcp net-fix net-name net-ping net-roam net-router net-scan net-report net-show net-tp-scan net-var net-watch
SBINS = net-mgr net-mgr-setup net-dns net-mgr-relay
UNITS = net-mgr.service net-dns.service net-mgr-relay.service
MAN1S = net-alias.1 net-discover.1 net-fix.1 net-gen-dnsmasq.1 \
        net-import-dhcp.1 net-name.1 net-ping.1 net-poll-ap.1 \
        net-report.1 net-roam.1 net-router.1 net-scan.1 net-show.1 \
        net-tp-scan.1 net-var.1 net-watch.1
MAN7S = net-mgr.7
LIBS  = NetMgr/Where.pm NetMgr/Protocol.pm NetMgr/Config.pm NetMgr/DB.pm \
        NetMgr/Manager.pm NetMgr/Client.pm NetMgr/Resolver.pm \
        NetMgr/Relay.pm NetMgr/Vendor.pm NetMgr/Subnets.pm \
        NetMgr/Producer/AP.pm NetMgr/Producer/Scan.pm \
        NetMgr/Producer/DhcpMaster.pm NetMgr/Producer/Fingerprint.pm

INSTALL ?= install

.PHONY: list install setup deps uninstall test check clean help

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
	@echo "  creates MySQL database 'netmgr' and writes /root/.my.cnf [net-mgr] section"
	@echo "  (run 'make setup' standalone to do just this step)"
	@echo
	@echo "vars: PREFIX=$(PREFIX)  DESTDIR=$(DESTDIR)  SYSCONFDIR=$(SYSCONFDIR)"
	@echo
	@echo "--- dependency check ---"
	@$(MAKE) -s deps || true

# --- install ----------------------------------------------------------
install:
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
	$(INSTALL) -d $(DESTDIR)$(PERL5DIR)/NetMgr/Producer
	$(INSTALL) -d $(DESTDIR)$(SHAREDIR)/sql
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/net-mgr
	$(INSTALL) -d $(DESTDIR)$(UNITDIR)
	@for f in $(BINS); do \
	  echo "  bin/$$f → $(DESTDIR)$(BINDIR)/$$f"; \
	  sed -e 's|use lib .*FindBin.*|use lib "$(PERL5DIR)";|' \
	      bin/$$f > $(DESTDIR)$(BINDIR)/$$f.tmp && \
	  mv $(DESTDIR)$(BINDIR)/$$f.tmp $(DESTDIR)$(BINDIR)/$$f && \
	  chmod 755 $(DESTDIR)$(BINDIR)/$$f; \
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
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	  systemctl daemon-reload; \
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
	@CFG=$(DESTDIR)$(SYSCONFDIR)/net-mgr/config; \
	  perl -Ilib -MNetMgr::Config -e 'my @d = NetMgr::Config::dead_keys($$ARGV[0]); exit unless @d; print STDERR "\nWARN: $$ARGV[0] has keys no longer read by the daemon:\n"; print STDERR "  $$_\n" for @d; print STDERR "(harmless, but you can delete them.)\n"' "$$CFG"
	@echo
	@echo "Files installed."
	@if [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = "0" ]; then \
	  if [ ! -f /root/.my.cnf ] || ! grep -q '^\[net-mgr\]' /root/.my.cnf 2>/dev/null; then \
	    echo; \
	    echo "Running first-time DB setup..."; \
	    $(DESTDIR)$(SBINDIR)/net-mgr-setup; \
	  else \
	    echo "(/root/.my.cnf already has [net-mgr] section — skipping setup)"; \
	  fi; \
	  echo; \
	  echo "Enable + start the services:"; \
	  echo "  systemctl enable --now net-mgr.service"; \
	  echo "  systemctl enable --now net-dns.service     # optional: DNS frontend"; \
	else \
	  echo; \
	  echo "Next: sudo make setup           (or: sudo $(SBINDIR)/net-mgr-setup)"; \
	  echo "Then: sudo systemctl enable --now net-mgr.service"; \
	fi

# --- setup (interactive DB + creds bootstrap) ------------------------
setup:
	@if [ "$$(id -u)" != "0" ]; then \
	  echo "setup must run as root (it writes /root/.my.cnf)"; exit 1; \
	fi
	$(DESTDIR)$(SBINDIR)/net-mgr-setup

# --- uninstall (does not remove /etc/net-mgr/ or /root/.my.cnf) ---
uninstall:
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	  for u in $(UNITS); do \
	    systemctl disable --now "$$u" 2>/dev/null || true; \
	  done; \
	fi
	@for f in $(BINS);  do rm -fv $(DESTDIR)$(BINDIR)/$$f;  done
	@for f in $(SBINS); do rm -fv $(DESTDIR)$(SBINDIR)/$$f; done
	@for f in $(LIBS);  do rm -fv $(DESTDIR)$(PERL5DIR)/$$f; done
	@for f in $(UNITS); do rm -fv $(DESTDIR)$(UNITDIR)/$$f; done
	@for f in $(MAN1S); do rm -fv $(DESTDIR)$(MANDIR)/man1/$$f; done
	@for f in $(MAN7S); do rm -fv $(DESTDIR)$(MANDIR)/man7/$$f; done
	@rm -fv $(DESTDIR)$(CGIDIR)/net-mgr-web.cgi 2>/dev/null || true
	@rm -fv $(DESTDIR)$(APACHE_CONF_DIR)/net-mgr.conf 2>/dev/null || true
	@rm -fv $(DESTDIR)$(SHAREDIR)/sql/schema.sql
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
	@for f in $(LIBS); do perl -Ilib -c lib/$$f || exit 1; done
	@for f in $(BINS);  do perl -Ilib -c bin/$$f  || exit 1; done
	@for f in $(SBINS); do perl -Ilib -c sbin/$$f || exit 1; done
	@echo "compile: ok"

clean:
	@true

help: list

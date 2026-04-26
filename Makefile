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
SYSCONFDIR ?= /etc
DESTDIR    ?=

BINS  = net-alias net-poll-ap net-discover net-import-dhcp net-fix net-scan net-report net-show
SBINS = net-mgr net-mgr-setup
LIBS  = NetMgr/Where.pm NetMgr/Protocol.pm NetMgr/Config.pm NetMgr/DB.pm \
        NetMgr/Manager.pm NetMgr/Client.pm NetMgr/Resolver.pm \
        NetMgr/Vendor.pm NetMgr/Subnets.pm \
        NetMgr/Producer/AP.pm NetMgr/Producer/Scan.pm \
        NetMgr/Producer/DhcpMaster.pm

INSTALL ?= install

.PHONY: list install setup deps uninstall test check clean help

# --- dependency check (Debian/Ubuntu apt names) ----------------------
# Each check_X writes its apt package name to $$miss if its probe fails.
# `make deps` exits 1 with an apt install command when anything is missing.

deps:
	@miss=""; \
	check() { \
	  if /bin/sh -c "$$1" >/dev/null 2>&1; then \
	    printf "  ok      %-20s %s\n" "$$2" "$$3"; \
	  else \
	    printf "  MISSING %-20s %s\n" "$$2" "$$3"; \
	    miss="$$miss $$2"; \
	  fi; \
	}; \
	check 'command -v nmap'           nmap              'nmap (discovery sweep)'; \
	check 'command -v fping'          fping             'fping (presence check)'; \
	check 'command -v ssh'            openssh-client    'ssh client (AP polling)'; \
	check 'command -v ip'             iproute2          'ip command (auto-detect networks)'; \
	check 'command -v mysql'          mariadb-client    'mysql client (setup script)'; \
	check 'perl -MDBI -e 1'           libdbi-perl       'Perl DBI'; \
	check 'perl -MDBD::mysql -e 1'    libdbd-mysql-perl 'Perl DBD::mysql'; \
	check 'dpkg -l mariadb-server 2>/dev/null | grep -q "^ii " || dpkg -l mysql-server 2>/dev/null | grep -q "^ii "' \
	                                  mariadb-server    'MySQL/MariaDB server'; \
	miss=$$(echo $$miss | tr ' ' '\n' | sort -u | tr '\n' ' '); \
	miss=$${miss% }; miss=$${miss# }; \
	if [ -n "$$miss" ]; then \
	  echo; \
	  echo "install missing packages with:"; \
	  echo "  sudo apt install -y $$miss"; \
	  exit 1; \
	else \
	  echo; \
	  echo "all dependencies present"; \
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
install: deps
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL) -d $(DESTDIR)$(PERL5DIR)/NetMgr/Producer
	$(INSTALL) -d $(DESTDIR)$(SHAREDIR)/sql
	$(INSTALL) -d $(DESTDIR)$(SYSCONFDIR)/net-mgr
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
	  echo "Start the daemon: $(SBINDIR)/net-mgr"; \
	else \
	  echo; \
	  echo "Next: sudo make setup           (or: sudo $(SBINDIR)/net-mgr-setup)"; \
	  echo "Then: sudo $(SBINDIR)/net-mgr"; \
	fi

# --- setup (interactive DB + creds bootstrap) ------------------------
setup:
	@if [ "$$(id -u)" != "0" ]; then \
	  echo "setup must run as root (it writes /root/.my.cnf)"; exit 1; \
	fi
	$(DESTDIR)$(SBINDIR)/net-mgr-setup

# --- uninstall (does not remove /etc/net-mgr/ or /root/.my.cnf) ---
uninstall:
	@for f in $(BINS);  do rm -fv $(DESTDIR)$(BINDIR)/$$f;  done
	@for f in $(SBINS); do rm -fv $(DESTDIR)$(SBINDIR)/$$f; done
	@for f in $(LIBS);  do rm -fv $(DESTDIR)$(PERL5DIR)/$$f; done
	@rm -fv $(DESTDIR)$(SHAREDIR)/sql/schema.sql
	-@rmdir $(DESTDIR)$(PERL5DIR)/NetMgr/Producer 2>/dev/null || true
	-@rmdir $(DESTDIR)$(PERL5DIR)/NetMgr          2>/dev/null || true
	-@rmdir $(DESTDIR)$(SHAREDIR)/sql             2>/dev/null || true
	-@rmdir $(DESTDIR)$(SHAREDIR)                 2>/dev/null || true
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

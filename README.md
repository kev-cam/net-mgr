# net-mgr

A network-management daemon plus a family of `net-*` CLI tools. The daemon
(`net-mgr`) observes the network into a MariaDB/MySQL database (machines,
interfaces, addresses, APs, DHCP leases, …), serves it over a small line
protocol, and can act on it (firewall, gateway, port forwards). Instances on
different hosts mesh and replicate via an elected master. It also hosts
`net-chat`, a coordination chat with per-chat file archives.

See the man pages (`net-mgr(7)`, `net-chat(1)`, `net-lookup(1)`, …) for tool
detail, and `etc/config.sample` for every config knob.

## Requirements

Perl with `DBD::mysql`, MariaDB/MySQL, and the usual net tools (`ip`, `fping`,
`nmap`, `ssh`). `make deps` lists anything missing.

## Install (local)

```sh
sudo make install
```

This installs the binaries, Perl modules (`→ /usr/local/share/perl5`), SQL
schema, man pages, and systemd units; rewrites each script's `use lib` to the
install path; and, the first time as root, runs first-time DB setup
(`make setup`) — it creates the `netmgr` database and writes the credentials
to **`/etc/net-mgr/root.conf`** (the `[net-mgr]` group; the generic
`/root/.my.cnf` is deprecated but still honored with a warning).

`make list` (or `make help`) prints the full install plan and a dependency
check without changing anything. If a dependency is flagged and you want to
proceed anyway, use `make install FORCE=1`.

Then enable the services:

```sh
sudo systemctl enable --now net-mgr net-dns net-mgr-relay
```

## Install on a remote host

`install-on` rsyncs the working tree to a host and runs `make install` there
(no git needed on the remote):

```sh
make install-on TARGET=nas3 SUDO=sudo
make install-on TARGET=root@gateway3
make install-on TARGET=nas3 SSHOPTS='-p 2222 -i ~/.ssh/firewall' MAKEARGS='FORCE=1'
```

| Option | Meaning |
| --- | --- |
| `TARGET=` *(required)* | `[user@]host` to install on |
| `SUDO=sudo` | run the remote `make install` under sudo (adds `ssh -t` for the prompt) |
| `SSHOPTS=` | ssh options, e.g. `'-p 2222 -i ~/.ssh/key'` |
| `MAKEARGS=` | passed to the remote `make install`, e.g. `'FORCE=1'` |
| `KEEP=1` | leave the staged copy on the remote (default: remove it) |
| `REMOTE_TMP=` | staging dir on the remote (default `/tmp/$USER/net-mgr`) |

## Deploying to the fleet

List your hosts once in the `[deploy]` section of the config (`make deploy`
reads `/etc/net-mgr/config` by default, or `DEPLOY_CONF=`), then deploy to all
of them with one command:

```ini
# /etc/net-mgr/config
[deploy]
hosts     = nas3, bigsony, clevo
sudo      = sudo                       # optional: run remote installs as root
ssh_opts  = -p 2222 -i ~/.ssh/firewall # optional: applied to every host
make_args = FORCE=1                    # optional: passed to remote make install
```

```sh
make deploy                      # install on every [deploy] host (via install-on)
make deploy DEPLOY_CONF=./my.conf
```

The `[deploy]` section is build-host tooling only — the daemon never reads it.
The `sudo`/`ssh_opts`/`make_args` knobs apply to every host; for per-host
differences, run `install-on` directly.

## Uninstall

```sh
sudo make uninstall   # removes installed files; leaves /etc/net-mgr/ and the DB
```

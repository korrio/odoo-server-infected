# Odoo 7 server compromise: PostgreSQL cryptojacking (XMRig)

Incident report and forensic evidence from an Odoo 7 + PostgreSQL 9.6 Docker host. The client reported that Odoo pages were very slow. The cause was a cryptominer running inside the Postgres container, not user traffic.

- **Status:** **Contained and remediated 2026-09-17 02:51 UTC** (see [Remediation performed](#remediation-performed-2026-09-17))
- **Collected:** 2026-09-17 02:18 UTC (live system, before any remediation)
- **Host:** DigitalOcean droplet, 2 vCPU / 4 GB RAM / no swap, Ubuntu 24.10, Docker
- **Stack:** `akolpakov/odoo:7` (OpenERP 7.0-20170329) + `postgres:9.6`

> **Redaction notice:** this repository is public. Server IP, hostname, database password, Odoo `session_id` tokens and SSH key fingerprints are replaced with `<REDACTED>` / `<SERVER_IP>` / `<HOSTNAME>`. Every public IPv4 address except the C2 is masked to `a.b.x.x`. **Malware binaries are not included**, only hashes and extracted strings.

## Summary

1. PostgreSQL port `5432` was published to the internet (`docker/docker-compose.yml.bak.1777676021`), with a superuser account using a weak default password and `pg_hba.conf` set to `host all all all md5`.
2. The attacker logged in as a superuser and wrote a malicious shared library, `gcmanager-1.so`, into `PGDATA`. They then added it to `shared_preload_libraries` and `session_preload_libraries` in `postgresql.conf`.
3. On every Postgres start, the library forks a process disguised as `postgres: walwriter`. That process drops a loader into `/var/tmp/.<random>/`, and the loader downloads and runs a UPX-packed **XMRig** miner, also disguised as `postgres: walwriter`.
4. Closing port 5432 on 2026-05-01 did **not** remove the infection. The library lives in the bind-mounted data directory, so it survived the container being recreated.
5. The miner used about 200% CPU (both cores) and about 2.4 GB RAM. Odoo was left with almost no CPU and no page cache, and that was the slowness the client saw.

## Timeline (UTC)

| Time | Event | Evidence |
|---|---|---|
| 2024-11-02 | Postgres data directory created (Odoo 7 migration) | `postgres/stat.txt` (postgresql.conf birth) |
| **2026-02-25 19:05:40** | **`gcmanager-1.so` created in PGDATA (initial compromise)** | `postgres/stat.txt` (Birth) |
| 2026-02-25 19:05:42 | `postgresql.conf` modified to preload the library | `postgres/stat.txt` (Modify) |
| 2026-05-01 11:52:12 | `gcmanager-1.so` rewritten (payload update) | `postgres/stat.txt` (Modify) |
| 2026-05-01 22:53:41 | Admin backs up compose file; new compose removes `5432:5432` | `docker/docker-compose.yml*` |
| 2026-05-01 22:57:51 | `odoo-db` container recreated and Postgres starts | `postgres/container_log.txt` |
| 2026-05-01 22:57:53 | Loader dropped: `/var/tmp/.wpmocdevxz/xbbqewcner` + lock `/var/tmp/.lckktfdd`, 2 s after start | `docker/odoo-db_tmp_listing.txt` |
| 2026-05-03 onward | A new miner spawns every 1–2 days, then daily; 133 dead (zombie) miner processes accumulate | `process/zombies.txt` |
| 2026-09-17 00:30:36 | Current miner dropped: `/var/tmp/.ytagwyaegn/mgqipgiuvp`, connected to C2/pool | `process/`, `network/odoo-db_ss.txt` |
| 2026-08-09 15:39:46 | Remote `POST /web/database/duplicate` from `111.90.x.x` using the default master password; **failed** (`TypeError: duplicate() got an unexpected keyword argument 'new_name'`, a scanner built for newer Odoo). The only database-manager action in the log | `logs/odoo_container_json.log.gz` |
| 2026-09-17 02:18 | Evidence collected | `collected_at_utc.txt` |
| 2026-09-17 02:46 | Verified database backups taken | none (server only) |
| 2026-09-17 02:48–02:50 | Persistence removed, containers recreated, credentials rotated (Odoo outage about 2 min) | none (server only) |
| 2026-09-17 02:51 | SSH hardened, C2 blocked, remediation verified | none (server only) |

## Indicators of compromise

### Files
| SHA-256 | Name / path | Type | Role |
|---|---|---|---|
| `54c819113ecfa5f7e5b1546c738e0cae025d4097dc19eeb730651ce76d7d251c` | `$PGDATA/gcmanager-1.so` | ELF64 shared object, static-pie, stripped | Persistence: Postgres preload library, masquerades as Postgres background workers |
| `52422f2470fcccfbc40e55bb5c273ad3db947e92ec0474f83ddf423a2c50cf5b` | `/var/tmp/.wpmocdevxz/xbbqewcner` | ELF64 static, stripped (embeds libcurl) | Downloader/loader (string `/lin/64/xmrig`) |
| `287bd345c4cd16737ab999d8f9fd08ebb9411d09d06c35aa4869d65db31367e1` | `/var/tmp/.ytagwyaegn/mgqipgiuvp` | ELF64 static, UPX 4.02 packed | XMRig miner |

MD5s are in `samples_md5.txt`, and `file` output is in `samples_file.txt`.

### Network
- `185.10.68.220:443` (outbound TCP from the Postgres container, held by the miner)

### Host and process artifacts
- `shared_preload_libraries` / `session_preload_libraries` pointing to a `.so` inside `PGDATA`
- Processes named `postgres: walwriter` (note: the real process is `postgres: wal writer process` on 9.6) whose `/proc/<pid>/exe` is under `/var/tmp/`
- Hidden dirs `/var/tmp/.<10 lowercase letters>/<10 lowercase letters>`, plus a zero-byte lock file `/var/tmp/.<8 letters>`
- Many zombie child processes with random 10-letter names, owned by uid 999 (postgres)
- Strings in `gcmanager-1.so`: `/dev/shm/tmp-%d`, `/etc/postgresql`, `/var/lib/postgresql`, `/var/tmp`, fake names `postgres: autovacuum launcher|background writer|checkpointer|logical replication launcher|stats collector|walwriter`

### Quick check on other Postgres hosts
```sh
psql -Atc "show shared_preload_libraries; show session_preload_libraries"
ps -eo pid,args | grep 'postgres: walwriter$' | while read p _; do ls -l /proc/$p/exe; done
find / -path '*/var/tmp/.*' -type f -perm -u+x 2>/dev/null
```

## Why Odoo was slow

Evidence: `system/`, `logs/odoo_container_json.log.gz`

- **Load:** `vmstat` shows 98–99% user CPU and 0% idle. CPU pressure `some avg60=23`.
- **Memory:** `odoo-db` container at 3.05 GiB / 3.82 GiB, about 150 MB free, no swap. The 635 MB database can't fit in page cache.
- **Traffic is normal:**
  - 564k requests from 2026-05-01 to 09-17, about 5k per day, during Thai business hours (01–10 UTC), near zero on weekends
  - Busiest second: 52 requests
  - 84% of requests are `POST /web/dataset/call_kw`
  - 121 × HTTP 500
- **Internet exposure of Odoo:** port 8069 is reachable from anywhere, even though UFW has a single-IP allow rule, because Docker-published ports skip UFW. Scanners probe `/..%2F..%2Fetc%2Fpasswd`, `/HNAP1`, `/cgi-bin/*`, and `/web/database/get_list` (146 hits, database manager exposed).
- **Odoo master password was the default:** the host's `openerp-server.conf` was **never mounted** into the container. Odoo ran with the image's built-in config, where `admin_passwd` is unset, so the master password was `admin`. Anyone on the internet could back up, duplicate or drop the database through the database manager.

Secondary issues (not the root cause):
- Odoo runs as a single threaded process. The `workers`/`limit_*` tuning in the host's `openerp-server.conf` never applied, because that file was not mounted.
- `akolpakov/odoo:7`'s entrypoint passes `--db_password` on the command line, so the DB password was visible to any `ps` on the host.
- No reverse proxy: `/web/webclient/js` (1.17 MB) is served uncompressed.
- `sale_order_line` has never been autovacuumed. There are heavy sequential scans on `sale_order_line`, `product_product` and `product_template`.
- End-of-life software: Odoo 7, PostgreSQL 9.6, Ubuntu 24.10.

## Remediation performed (2026-09-17)

Each step was verified on the live host after it was applied.

| Area | Before | After | Verification |
|---|---|---|---|
| Backup | none | `pg_dump -Fc` of all databases + globals, `postgresql.conf` and compose file copied | `pg_restore -l` lists 365 table-data entries |
| Persistence | `gcmanager-1.so` preloaded by `postgresql.conf` | Library moved to a root-only quarantine dir (mode `000`); both preload lines commented out; containers recreated (fresh `/var/tmp`) | `show shared_preload_libraries` is empty; no `/var/tmp` artifacts; 0 zombie processes; CPU 100% idle, 3 GB RAM free |
| C2 | Outbound connection allowed | `185.10.68.220` dropped in `DOCKER-USER` and `OUTPUT`, persisted by a systemd oneshot unit started after `docker.service` | `iptables -S` shows the rules |
| Postgres credentials | `odoo`/`odoo`, app role was superuser | New random passwords for `odoo` and `postgres`; `odoo` is `NOSUPERUSER CREATEDB` (still owns its database) | Old password rejected (`password authentication failed`); Odoo connects |
| DB password exposure | Passed as `--db_password` argv | Stored in the Odoo config file (mode `600`, owned by the Odoo uid); env var removed from the Odoo service, so the entrypoint no longer adds it to argv | `ps` shows no `db_password` |
| Odoo config | Host config not mounted; master password `admin` | Config mounted read-only with a strong random `admin_passwd` and `dbfilter = ^erp2023$` | Database backup with `admin` returns `AccessDenied`; `get_list` returns only the production database |
| SSH | Root password login enabled (`50-cloud-init.conf`) | `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin prohibit-password`; root password rotated (DigitalOcean console only) | Key login works; password login returns `Permission denied (publickey)` |
| Compose | Obsolete `version:` key; DB password hard-coded | Secrets moved to a mode-`600` `.env`; `5432` never published | `docker compose config -q` passes |
| Reverse proxy / TLS (03:09 UTC) | Odoo served directly over plain HTTP on published port 8069 | nginx 1.27 container in front of Odoo with a Let's Encrypt certificate (sslip.io hostname), TLS 1.2/1.3, HSTS, gzip, 7-day cache for `/*/static/`; Odoo no longer published (`proxy_mode = True`); ports 80 and 8069 answer with `301` to HTTPS (8069 kept for a transition period); `/web/database/{backup,restore,drop,duplicate,create,change_password}` return `403`; renewal via cron twice daily | External checks: HTTPS `200` with a valid chain; `:8069` and `:80` return `301`; `webclient/js` 1.17 MB → 506 KB gzip; static `X-Cache: HIT`; database backup `403`; `certbot renew --dry-run` succeeds |

**Impact of remediation:** Odoo was unavailable from 02:48:13 to 02:50:21 UTC, plus a 4-second restart at 02:51 and about 4 seconds at 03:09 for the proxy switch. Existing web sessions were invalidated.

**Lessons:**
- Closing the port on 2026-05-01 hid the symptom of the intrusion but left its persistence in `PGDATA`. After a database compromise, always check the preload settings and the data directory itself.
- Docker-published ports bypass UFW. Firewall them in `DOCKER-USER` or bind them to `127.0.0.1`.
- Confirm that a config file is actually mounted before relying on it (`docker exec <container> cat <path>`).

## Still open

1. **Data exposure assessment:** the attacker had PostgreSQL superuser access from 2026-02-25 to 2026-09-17. Treat business data and Odoo user password hashes as exposed. Reset Odoo user passwords and inform the data owner.
2. **Transition:** after users have moved to the HTTPS address, remove the `8069` port from the nginx service. Optionally move from the sslip.io hostname to the client's own domain.
3. **Monitoring:** CPU alert on the droplet (for example, above 70% for 10 minutes) to catch a recurrence within hours.
4. **Performance:** enable Odoo workers, `VACUUM ANALYZE`, and add indexes / `pg_trgm` for product and sales-line searches. Add swap.
5. **Lifecycle:** upgrade off end-of-life Odoo 7, PostgreSQL 9.6 and Ubuntu 24.10.

## Repository layout

| Path | Contents |
|---|---|
| `evidence/system/` | ps (forest + start times), vmstat, free/df, docker stats, ufw/iptables, sshd auth settings, fail2ban |
| `evidence/process/pid_*/` | `/proc` of the loader (164475) and the miner (2693213): exe/cwd links, cmdline, environ, status, maps, fds |
| `evidence/process/zombies.txt` | 133 dead miner children with spawn times |
| `evidence/network/` | socket tables for host and Postgres container namespace (C2 connection) |
| `evidence/docker/` | `docker inspect`, current and previous compose files, `/var/tmp` listing with full timestamps |
| `evidence/postgres/` | `postgresql.conf`, `postgresql.auto.conf`, `pg_hba.conf`, `stat` of malicious files, container log, role/setting/function queries |
| `evidence/logs/` | Odoo container log (werkzeug access + app log, gzip), SSH auth log tail |
| `evidence/samples_*.txt` | SHA-256 / MD5 / `file` of the collected binaries (binaries not published) |

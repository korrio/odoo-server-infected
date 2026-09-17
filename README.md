# Odoo 7 server compromise: PostgreSQL cryptojacking (XMRig)

Incident report and forensic evidence from an Odoo 7 + PostgreSQL 9.6 Docker host. The client reported that Odoo pages were very slow. The cause was a cryptominer running inside the Postgres container, not user traffic.

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
| 2026-09-17 02:18 | Evidence collected | `collected_at_utc.txt` |

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

Secondary issues (not the root cause):
- `openerp-server.conf` has inline `# comments` on `workers`/`limit_*` lines, and Odoo runs as a single threaded process.
- No reverse proxy: `/web/webclient/js` (1.17 MB) is served uncompressed.
- `sale_order_line` has never been autovacuumed. There are heavy sequential scans on `sale_order_line`, `product_product` and `product_template`.
- End-of-life software: Odoo 7, PostgreSQL 9.6, Ubuntu 24.10.

## Remediation

1. **Backup:** `pg_dump` the business database and copy `pg_data/` somewhere offline.
2. **Remove persistence:**
   - Delete both `*_preload_libraries` lines from `pg_data/postgresql.conf`.
   - Delete `pg_data/gcmanager-1.so`.
   - Run `docker compose down && docker compose up -d`. Recreating the container wipes `/var/tmp`.
3. **Verify:** `show shared_preload_libraries` is empty, no `/var/tmp/.*` executables exist, no connection to `185.10.68.220`, CPU is back to idle.
4. **Hunt for more:**
   - unexpected roles
   - functions in C or untrusted languages (none found at collection: `postgres/queries.txt`)
   - modified `pg_hba.conf`
   - host-level persistence (none found at collection)
5. **Rotate credentials:**
   - Postgres password; Odoo must connect as a **non-superuser**
   - Odoo admin + master password (`list_db = False`)
   - Root/SSH password (password auth is enabled via `50-cloud-init.conf`); switch to key-only login
6. **Network:**
   - Never publish 5432.
   - Bind Odoo to `127.0.0.1:8069` behind nginx + TLS, or filter in the `DOCKER-USER` iptables chain.
   - Block egress to `185.10.68.220`.
7. **Monitoring:** CPU alert on the droplet so a miner is caught in hours, not months.
8. **Performance afterwards:**
   - Fix the Odoo config so `workers` apply.
   - nginx gzip + static caching.
   - `VACUUM ANALYZE`, and add indexes / `pg_trgm` for product and sales-line searches.
   - Add swap.
   - Plan an upgrade off EOL versions.

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

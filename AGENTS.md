# Adama

Reactive scan bus. Tools self-subscribe on NATS JetStream (`EVENTS`, 24h). Scanner dedup includes `(tool, kind, value, scope)` and explicit endpoint identity; observation sinks bypass work dedup.

Read `README.md` for the event schema and tool graph. This file is how to change the code.

## Layout

- `event/` — kinds, v2 observation envelope/target, `SCHEMA.md`, `Live` / `MarkLive`, activity
- `sdk/` — connect, subscribe, dedup, gate (`allow`/`deny`/`NeedLive`), activity notes
- `cmd/<tool>/` — one worker each; nmap-quick/http/full share `cmd/nmap` + a profile; `export` is the durable JSONL sink
- `profiles/*.yaml` — tool flags (`NMAP_PROFILE`, `HTTPX_PROFILE`, `NUCLEI_PROFILE`)
- `profiles/runs/` — seed `--profile` kits
- `internal/nmapx`, `internal/asurl` — shared parse / HTTP detect

## Conventions

- Do not invent event kinds. Emit the existing ones (`domain`, `fqdn`, `netblock`, `ip`, `port`, `service`, `url`, `screenshot`, `finding`).
- Preserve observed host/name/port/protocol pairs and `name_role`; never infer responding IPs from ancestor alias lists. Put results in `info`; the SDK supplies run/scan/parent/input lineage.
- Put nmap/httpx/nuclei flags in YAML, not hardcoded in Go.
- `-Pn` scanners use `NeedLive: true`. Only `nmap-discover` (or another probe) sets `meta.alive=true`.
- `nmap-full` is IP-only. Quick/http also take live `fqdn` so vhosts get SNI ports.
- HTTP tools listen on `url`, not raw `port`. `as-url` translates http(s) `service` → `url`. `nuclei-net` takes non-web `service`.
- `tlsx` runs on every open `port`.
- `ctl` filters CT names with dnsx itself; `dnsx` worker is domain wordlist only.
- Nmap emits open ports only (`--open`).
- Seed `allow`/`deny`/`scope` inherit to children. Gate runs before the KV lock.

## Commands

```bash
mise exec go -- go test ./...
docker compose up -d --build
docker compose run --rm seed ip 192.168.1.1
```

Go via mise (`go@1.24+`). Watch: `http://127.0.0.1:8080`. Report: `reports/report.html`. Export: `exports/events.jsonl`.

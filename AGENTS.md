# Adama

Reactive scan bus. Tools self-subscribe on NATS JetStream (`EVENTS`, retained until explicit cleanup). Durable work identity includes `(tool, kind, value, scope)` and explicit endpoint identity; observation sinks use event IDs.

Read `README.md` for the event schema and tool graph. This file is how to change the code.

## Layout

- `event/` — kinds, v2 observation envelope/target, `SCHEMA.md`, `Live` / `MarkLive`, activity
- `sdk/` — connect, subscribe, durable work leases/outboxes/budgets, gates, activity; see `sdk/WORKFLOW.md`
- `cmd/<tool>/` — one worker each; nmap-quick/http/full share `cmd/nmap` + a profile; `export` is the durable JSONL sink
- `profiles/*.yaml` — tool flags (`NMAP_PROFILE`, `HTTPX_PROFILE`, `NUCLEI_PROFILE`)
- `profiles/runs/` — seed `--profile` kits
- `internal/nmapx`, `internal/asurl` — shared parse / HTTP detect
- `internal/reconcile`, `cmd/reconcile`, `cmd/resolve` — persistent name/endpoint joins and A/AAAA resolution
- `internal/toolrun`, `cmd/work` — subprocess failure classification and task/tool status
- `sdk/registry.go`, `sdk/rule.go`, `internal/coverage` — worker self-registration, shared declarative eligibility, and desired-work snapshots
- `scripts/register-workers.py` — Compose-derived registration/inventory; no separate tool list
- `internal/webprobe`, `cmd/web-probe` — bounded, IP-bound HTTP identification for unclassified TCP services

## Conventions

- Do not invent event kinds. Emit the existing ones (`domain`, `fqdn`, `netblock`, `ip`, `port`, `service`, `url`, `screenshot`, `finding`).
- Preserve observed host/name/port/protocol pairs and `name_role`; never infer responding IPs from ancestor alias lists. Put results in `info`; the SDK supplies run/scan/parent/input lineage.
- Put nmap/httpx/nuclei flags in YAML, not hardcoded in Go.
- `-Pn` scanners use `NeedLive: true`. Only `nmap-discover` (or another probe) sets `meta.alive=true`.
- `nmap-full` is IP-only. Quick/http also take live `fqdn` so vhosts get SNI ports.
- HTTP tools listen on `url`, not raw `port`. `as-url` translates http(s) `service` → `url`. `nuclei-net` takes non-web `service`.
- `web-probe` identifies HTTP on unclassified `service` inputs; preserve the observed IP and requested Host/SNI, and never loop on its diagnostic outputs.
- `tlsx` runs on every open `port`.
- `ctl` filters CT names with dnsx itself; `dnsx` worker is domain wordlist only.
- Nmap emits open ports only (`--open`).
- Seed `allow`/`deny`/`scope` inherit to children. Gate runs before the KV lock.
- Errors are terminal unless explicitly retryable; never swallow a subprocess failure or clear task state to retry. Shared configuration faults pause the tool. Persist partial observations with the failure.
- Terminal task state has no TTL. Use a new scope for an explicit rescan; run IDs alone do not reset budgets. Do not automatically recycle failed work.
- Declare eligibility once with `sdk.Config.Filter` rules; execution and coverage use the same serialized rules. SDK registers before consuming. Use `Setup` for runtime initialization that must be skipped in `ADAMA_REGISTER_ONLY=1` mode.
- Label new Compose worker services with `<<: *worker`; the registration script discovers them. Never add a central worker-name registry.

## Commands

```bash
mise exec go -- go test ./...
docker compose up -d --build
docker compose run --rm seed ip 192.168.1.1
```

Go via mise (`go@1.24+`). Watch: `http://127.0.0.1:8080`. Report: `reports/report.html`. Export: `exports/events.jsonl`.

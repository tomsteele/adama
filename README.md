# adama

A reactive passive and active discovery process.

Tools subscribe themselves. Events live 24h. Dedup is per `(tool, kind, value)`.

POC: seed an FQDN **or** a netblock. A netblock is not exploded at seed time — `discover` (`nmap -sn`) emits live `ip`s (and PTR `fqdn`s); existing nmap/gowitness/nmap-svc pick them up.

Report worker POSTs `screenshot` and `service` events to `REPORT_URL`. With no URL it writes `reports/events.jsonl` and rebuilds `reports/report.html`. Screenshot events carry the jpeg on `data`. Set `REPORT_KINDS` to add more.

```bash
docker compose up -d --build nats discover nmap nmap-svc gowitness report
docker compose run --rm seed fqdn example.com
# or: docker compose run --rm seed netblock 203.0.113.0/24
ls screenshots reports
# open reports/report.html
docker compose logs -f discover nmap nmap-svc gowitness report
```

Scan only hosts you are allowed to touch.

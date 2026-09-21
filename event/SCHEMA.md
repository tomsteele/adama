# Observation contract, version 2

Workers accept one `event.Event` and return zero or more `event.Event` observations. The Go types are in [event.go](event.go) and [target.go](target.go); `Event.Canonical()` validates and normalizes the wire contract. The SDK supplies lineage and publishes the outputs. Existing event kinds and NATS subjects are unchanged.

Each result describes one subject or one name/address relationship. Explicit fields hold identity; `info` holds tool details. Consumers need no knowledge of Nmap XML, DNSX JSON, or inherited alias lists to interpret that identity.

## Envelope

| Field | JSON type | Meaning |
|---|---|---|
| `schema_version` | integer | `2` for new records. Unversioned/v1 records are accepted conservatively; unknown versions are rejected. |
| `id` | string | Unique observation ID assigned at publish. Transport redelivery retains it. |
| `run_id` | string | Inherited seed lineage. Defaults to the root event ID, or set with `seed --run`. |
| `scan_id` | string | One handler invocation/attempt. All its output records share this ID. A retried invocation gets a new ID. |
| `parent_id` | string | ID of the input event that caused this invocation. |
| `source` | string | Producing worker, such as `nmap-svc` or `nuclei-net`. |
| `probe` | string | Specific probe or template; defaults to the worker name. |
| `observed_at` | RFC 3339 timestamp | Tool timestamp when supplied, otherwise the publish time in UTC. |
| `kind`, `value` | strings | Existing routing kind and locator. `value` is not a unique entity or observation ID. |
| `input` | object | Triggering `kind`, `value`, and subject fields below; no recursive ancestry or result details. Omitted for root events. |
| `info` | object of strings | Result details. Keys and values are strings; documented structured values can contain JSON text. |
| `meta` | object of strings | Workflow `allow`, `deny`, `scope`, `profile`, and liveness `alive`, plus legacy compatibility fields. |
| `data`, `media_type` | strings | Optional base64 artifact and MIME type, currently screenshot images. |

The subject fields are flat at the top level and repeated inside `input` when relevant:

| Field | JSON type | Meaning |
|---|---|---|
| `host` | string | One IPv4/IPv6 address established for this subject. Never a hostname or comma-separated list. |
| `name` | string | One hostname. Lowercase, no trailing dot; international names must use their ASCII/punycode form. |
| `name_role` | string | Evidence connecting `name` to `host`, described below. Defaults to `observed` when only a name is supplied. |
| `port` | integer | 1–65535 when specified. Go's zero means unspecified/inapplicable and is omitted from JSON. |
| `proto` | string | `tcp`, `udp`, `icmp`, `icmpv6`, or `arp`. Omitted when unknown/inapplicable. ICMP and ARP cannot have a nonzero port. |
| `url` | string | HTTP(S) URL, preserving path/query/fragment case and encoding. |
| `sni` | string | TLS server name used or selected for the request. |
| `http_host` | string | HTTP authority, including an explicit port where present. |

`service` (string) and `tls` (boolean) accompany output observations but are not part of the input subject snapshot. `tls: true` represents TLS evidence or an HTTPS URL. Omitted/false is not proof that an endpoint never supports TLS.

Absent identity fields mean unknown or inapplicable, not a wildcard or permission to copy values from an ancestor. Literal IP seeds/URLs establish their own address; passive names can have no `host`. An `as-url` translation retains the service endpoint because it performs no new network request. A scanner records its own response IP instead of inheriting that field.

Canonicalization rejects contradictions between `value` and explicit host/name/port/URL/service fields. URL kinds derive their authority, port, SNI, and HTTP Host from the URL when those fields are absent. Port seeds default to TCP; legacy service records with no protocol remain unknown.

## Hostname evidence

| `name_role` | Meaning of the name/address pair |
|---|---|
| `requested` | This hostname was the selected target or request authority at this address. It is not a DNS RR assertion. |
| `dns_a`, `dns_aaaa` | A DNS answer explicitly associated this name with this IPv4/IPv6 address. Emit each answer separately. |
| `ptr` | A reverse lookup at this IP returned the name; this is not a forward lookup assertion. |
| `certificate_cn`, `certificate_san` | The TLS server at this IP/port presented a certificate containing the name. This does not establish where that name resolves. |
| `certificate_transparency` | A passive CT source mentioned the name; an IP is usually unknown. |
| `observed` | A name was mentioned without a more specific relationship. Consumers must not upgrade it to a DNS mapping. |

For active discovery, known `requested`/DNS name-address pairs can be probed at their explicit IP. Certificate and PTR discoveries are probed by the discovered hostname; the mentioning server's IP is not reused as its resolved address. Only discovery probes mark `meta.alive=true`. A DNS answer or certificate name alone does not prove liveness.

## Example

A service response is self-contained even if its triggering event has expired from the bus:

```json
{
  "schema_version": 2,
  "id": "observation-3",
  "run_id": "assessment-1",
  "scan_id": "scan-2",
  "parent_id": "observation-2",
  "source": "nmap-svc",
  "probe": "service-detection",
  "observed_at": "2026-09-20T12:00:00Z",
  "kind": "service",
  "value": "admin.example.com:8443/http",
  "host": "192.0.2.10",
  "name": "admin.example.com",
  "name_role": "requested",
  "port": 8443,
  "proto": "tcp",
  "service": "http",
  "tls": true,
  "input": {
    "kind": "port",
    "value": "admin.example.com:8443",
    "host": "192.0.2.10",
    "name": "admin.example.com",
    "name_role": "requested",
    "port": 8443,
    "proto": "tcp"
  },
  "info": {"product": "nginx", "version": "1.26.2"},
  "meta": {"scope": "assessment-1"}
}
```

If another response comes from `192.0.2.11`, it is a separate observation with that `host`, even if `value` is identical. A certificate SAN observed at `192.0.2.10:8443` has `kind: fqdn`, the SAN as `name`/`value`, and `name_role: certificate_san`. That record must not create a DNS A record for the SAN.

## Producer behavior

| Producer | Identity source |
|---|---|
| DNSX / CT resolver | One record per explicit A/AAAA answer, with its relationship role. CNAME/resolver details are JSON strings in `info`. |
| Nmap discovery | Actual XML address and explicit `up` status; requested names and PTR mentions remain distinct. |
| Nmap port/service | Actual XML address, port, transport, and service TLS tunnel. Inherited alias lists are not expanded into vhosts. |
| TLSX | Response IP, port, SNI, and separate CN/SAN roles. Non-hostname CN text and wildcards remain certificate details on emitted name records. |
| as-url | The service endpoint and HTTP/TLS evidence; scheme is not guessed from port 443. |
| HTTPX | Every JSONL result, response `host_ip` (or IP-valued legacy `host`), and the probed URL. DNS address lists are details, not proof of the responding IP. |
| Nuclei | Every match, response IP and matched URL/endpoint where the template output establishes them; template/matcher/extracted details in `info`. Unsupported or ambiguous template identity stays absent. |

HTTPX's HTTP probe and headless screenshot are separate operations. `info.endpoint_evidence=http_probe` limits the top-level IP assertion to the probe; it does not establish which backend served the browser navigation. Screenshot bytes use `info.screenshot_status=captured`; absent bytes use `missing`. `info.final_url` preserves redirect context; a changed authority sets `info.redirect_endpoint=unverified`. A reporter must not attach redirected page fingerprints or screenshot bytes to an asserted final IP using the initial IP. The upstream [HTTPX result type](https://github.com/projectdiscovery/httpx/blob/master/runner/types.go) and [probe/browser implementation](https://github.com/projectdiscovery/httpx/blob/master/runner/runner.go) define these separate sources. Exact browser endpoint capture remains follow-up work.

TLSX attempts TCP TLS even when triggered by an open UDP port, so its results use `proto: tcp`; they do not assert DTLS coverage. Findings from templates without reliable endpoint metadata can retain only the known subject fields and the original `input`.

## Consumer contract

A reporting worker subscribes with `sdk.Config{Observe: true}` and its own durable name. This bypasses scanner work dedup but retains subscription filters, gates, acknowledgements, and bounded delivery attempts. Use an empty `Kinds` list to observe every existing kind. Include the reporter in any seed allowlist.

In a database transaction, record the observation by `id` and upsert the supported subject relationships. Commit before the handler returns success. Redelivery can repeat an ID; a separate invocation can produce a different ID for the same fact. Observation idempotency and entity upserts belong in that consumer.

Suggested entity identities within an assessment/scope:

| Entity | Fields |
|---|---|
| Address | `host` |
| Network endpoint | `host`, `proto`, `port` |
| Named endpoint | `host`, `proto`, `port`, requested `name`, `sni`, `http_host` |
| Web resource | Named endpoint plus `url`, preserving path/query case |
| Name relationship | `name_role`, `name`, `host`, and endpoint fields when present |
| Observation/artifact/finding evidence | `id`, with `run_id`, `scan_id`, `parent_id`, and `input` provenance |

Keep unresolved names without fabricating an endpoint. Preserve evidence roles and timestamps; later arrival does not necessarily mean later observation. Do not overwrite known identity with missing fields, infer all IP/port combinations from alias lists, or merge findings solely on `value` (multiple matchers can share it).

The existing HTML reporter is still a PoC viewer; this change supplies the observation feed for a normalized sink, not that database. Observations also do not certify scan completeness: a handler can produce no findings, and durable task outcomes, recovery, late-name/port joining, and failure classification remain separate workflow work. No new retry loop is added; JetStream's existing per-message `MaxDeliver: 5` remains. This is not yet a global retry budget across newly emitted messages for the same logical task.

## Compatibility and rollout

Legacy `meta` fields remain readable. Canonicalization copies result details into `info` and promotes explicit singular legacy address/port fields when possible. It never chooses an address from `ips`/`fqdns` lists. Legacy observations without trustworthy identity or lineage cannot be repaired by the schema; unknown fields stay absent. Native v2 records treat the typed fields as authoritative and do not import a missing IP from compatibility metadata.

Scanner dedup keys are now hashes of tool, kind, value, scope, host, name, name role, port, protocol, SNI, HTTP Host, and TLS. The key format is `v2/<sha256>`, which supports URLs and IPv6 safely and keeps separate backends, transports, and HTTP/TLS work distinct. Result-detail enrichment does not change a scanner work key. Report/export skip this work dedup entirely.

`run_id` groups provenance; `meta.scope` separates work. Reusing a scope across run IDs can reuse already-completed work. Choose a new scope for an independent assessment.

Existing pre-v2 KV keys do not match the new keys. Coordinate worker upgrades; replaying old events through upgraded scanners can schedule work again. This change does not replay, clear, or migrate live NATS state. Existing retention and consumer start policies still apply. A newly created sink is not automatically a historical replay of the entire stream.

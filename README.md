# Bhai WAF

A single-binary, rule-based HTTP reverse proxy and attack-story dashboard. No ML, CGO, certificate, external database, or hosted account is required for the local HTTP deployment.

## Quick start

Requires Go 1.24+ for this dependency set and Linux amd64 or arm64. Configure an HTTP upstream on `127.0.0.1:3000`, then:

```sh
CGO_ENABLED=0 go build -o bhai-waf ./cmd/bhai-waf
./bhai-waf
```

Proxy: `http://127.0.0.1:8080`; dashboard: `http://127.0.0.1:9090`; Prometheus metrics: `http://127.0.0.1:9090/metrics`. `-config configs/bhai-waf.yaml` overrides defaults. The default SQLite file is `bhai-waf.db` in the current working directory. Adjust `upstream`, `listen`, `dashboard`, `database`, `rate_limit`, `story`, and `threat` in the YAML config. `rules_dir` optionally points at a directory containing all nine YAML category files and enables hot reload; otherwise the 500 built-in rules are embedded. `scripts/generate_rules.py` reproduces the checked-in catalog.

## What is enforced

- An HTTP reverse proxy inspects path, query, selected headers, and up to 1 MiB of request body, then blocks, challenges, logs, or forwards according to the first highest-priority match. The catalog contains **500 explicitly enumerated, target-scoped rules** across SQLi (100), XSS (80), RCE (60), LFI (50), SSRF (40), XXE (30), scanner (60), bot (40), and custom (40). Some rules deliberately share a signature but inspect different request fields. Regexes are compiled at load/reload; literal signatures use Aho–Corasick. Regexes are RE2, not PCRE. Be prepared to tune false positives for your application.
- A per-peer-IP in-memory token bucket rejects excess requests (HTTP 429). Only the socket peer is trusted; forwarded IP headers are never accepted as an identity. Tor exit IPs are fetched from the configured Tor Project URL hourly, and VPN detection uses explicitly configured CIDR ranges. Feed failure leaves the last valid list in place; on a cold start without a feed, Tor detection is unavailable. VPN classification is **not** inferred from arbitrary IPs.
- Tor/VPN peers and matched challenge rules receive a signed, expiring JavaScript SHA-256 proof-of-work challenge. Clearance is bound to the peer IP for one hour. Deploy behind HTTPS to make the browser's Web Crypto API available outside localhost. A reverse proxy/load balancer is responsible for TLS termination if the public site uses HTTPS.
- Sessions correlate on a hash of peer IP, User-Agent, and optional JA3. The HTTP proxy does **not** have a JA3 value, so normal sessions use IP and UA. Five minutes of inactivity ends a session. Recon, scan, brute-force, injection, exfiltration indicators, and persistence indicators contribute to a timeline. Scores are deterministic and capped at 100. High scores block that peer for one hour; critical scores auto-block for 24 hours. The store uses SQLite WAL with default 30-day retention and exposes a `StoryStore` interface; the live stream uses an `events.Bus` interface. The SQLite vault retains active IP blocks across restarts. Live session caches, rule toggles, and reputation feeds remain in memory; none of these components are distributed across instances. Sessions are bounded to 10,000 and timelines to 500 events per session; long bursts can lose older timeline details while retaining counters.

## TLS observation: important boundary

`-libssl auto` (default) *attempts* a passive eBPF uprobe on the local `libssl.so.3` `SSL_write` symbol. The process needs kernel BPF/perf permissions and a supported system library. `-libssl /path/to/libssl.so.3` selects a library; `-libssl ''` disables it. The probe copies at most 256 plaintext bytes from each **outbound** `SSL_write`, entirely without obtaining a certificate. The app currently publishes only PID and byte count to its event bus, not the raw plaintext; this prevents inadvertent secret retention. It does not support other TLS libraries, OpenSSL `SSL_read`/incoming request payloads, HTTP/2 reconstruction, JA3 derivation, or blocking traffic inside other TLS processes. If attachment is unavailable the WAF logs a warning and the HTTP proxy continues. eBPF observation is **not** an inline HTTPS WAF and cannot replace terminating TLS before enforcement. Linux 4.18+ on amd64 and 5.5+ on arm64 are target baselines, but uprobe loading and exact helper availability still depend on kernel policy and capabilities; a compatible kernel alone does not grant access.

## API and safety

The dashboard and control API **only bind to a loopback address**; do not expose them without an authenticating reverse proxy. Key endpoints: `GET /api/stories` (optional `ip`, `verdict`, `since` filters), `GET /api/stories/{id}`, `GET /api/stories/live` (WebSocket), `GET /api/attackers/top`, `GET /api/phases/stats`, and `GET /api/rules`. POST JSON to `/api/stories/{id}/block`, `/api/stories/{id}/false-positive`, or `/api/rules/{id}` (`{"enabled":false}`) to take an action. An Origin check and JSON content type guard mutation requests. False-positive marking is an analyst annotation, not an automatic unblocking or disabling of a rule. PDF export and public story sharing are not implemented. Rule toggles and manual blocks are in-memory; persist any policy changes in YAML when running multiple instances. The embedded UI includes dashboard, architecture, live traffic, attack stories, rules, and threats views.

## Testing

```sh
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test -run '^$' -bench . ./internal/rules ./internal/story
```

Benchmarks exercise a representative non-matching request and session observation with in-memory event bus. Results vary by CPU, workload, regex payload, and store latency; a live HTTP proxy round trip has additional network/SQLite overhead.

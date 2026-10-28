# Repository Guidelines

`sub2sfm` is a single-binary Go service and embedded web tool that converts airport proxy subscriptions into Sing-box (v1.12+) configurations specifically tailored for **macOS SFM (Sing-box for Mac)**.

## Project Overview

- **Purpose**: Bridge upstream subscription formats (Clash/Meta YAML, Base64, and protocol URIs for Trojan, VLESS Reality/Vision, Hysteria 2, Shadowsocks, VMess) into production-grade Sing-box JSON.
- **macOS NetworkExtension Fixes**:
  - Resolves SSH disconnects via TUN `stack: "mixed"` (gVisor user space TCP stack) and direct SSH routing.
  - Eliminates PMTU black holes by standardizing on `mtu: 1500`.
  - Blocks DNS leaks: orders `geosite-cn` ahead of Fake-IP, suppresses Type 65 (HTTPS/ECH) DNS queries, and excludes `action: resolve`.
  - Plugs WebRTC IP leaks by intercepting STUN/TURN traffic (`WebRTC防护` outbound defaulting to `全局拦截`).
  - Mitigates IPv6 routing black holes by defaulting to `strategy: "ipv4_only"` and single IPv4 subnet.

## Architecture & Data Flow

The service follows a pipe-and-filter conversion pipeline:

```
[ Client Request ]
  ├── GET /sub?sub=...   ──> Handler.handleSub()
  ├── POST /api/convert   ──> Handler.handleConvert()
  └── GET / (Web UI)      ──> Handler.handleIndex() (Embedded HTML)
           │
           ▼
[ Subscription Resolver & Cache ] (`pkg/parser/cache.go`, `pkg/parser/parser.go`)
  ├── In-Memory TTL Cache (5m TTL, sync.RWMutex; bypass with refresh=1 or nocache=1)
  └── FetchSubscription() (Custom User-Agent, skips airport TLS cert verification)
           │
           ▼
[ Format Detection & Parsing ] (`pkg/parser/`)
  ├── Direct URIs: trojan://, vless://, hysteria2://, ss://
  ├── Clash/Meta YAML: "proxies:" token -> yaml.Unmarshal -> model.Node
  ├── Base64 Decoded: padded, re-dispatched to URI or YAML parser
  └── Output: []*model.Node + model.ConvertOptions
           │
           ▼
[ Sing-box Generator Engine ] (`pkg/builder/`)
  ├── BuildInbounds()   ──> TUN (utun, mixed stack, MTU 1500) + Mixed (127.0.0.1:2080)
  ├── BuildDNS()        ──> dns_direct (223.5.5.5) + dns_proxy (8.8.8.8) + dns_fakeip (198.18.0.0/15)
  ├── BuildOutbounds()  ──> Tag deduplication -> Selectors + URLTest + Protocol outbounds
  ├── BuildRoute()      ──> Sniff -> Hijack DNS -> STUN block -> Presets (geek/standard/global) -> Rulesets
  └── Assembly          ──> map[string]any structure -> json.MarshalIndent
           │
           ▼
[ HTTP JSON Response ] (application/json; charset=utf-8; inline singbox.json)
```

## Key Directories

- `pkg/model/` — Core domain representations: `Node` (proxy node attributes) and `ConvertOptions` (converter query flags).
- `pkg/parser/` — Subscription fetching, 5-minute thread-safe TTL cache, and protocol decoders (`parser.go`, `clash.go`, `trojan.go`, `cache.go`).
- `pkg/builder/` — Sing-box configuration compiler and rule assemblers (`builder.go`, `tun.go`, `dns.go`, `outbounds.go`, `route.go`).
- `pkg/server/` — HTTP routing, handler logic, query options parsing, and embedded Web UI (`handler.go`, `static/index.html`).
- `.github/workflows/` — CI pipelines (`ci.yml`, `release.yml`) for lint, test, coverage, and multi-arch builds.

## Development Commands

```bash
# Run locally from source
go run main.go -port 8080

# Run all unit tests
go test ./...

# Run tests with verbose output and coverage
go test -v -cover ./...

# Run a specific unit test by regex
go test -v -run '^TestBuildSingBoxConfig_CoreRequirements$' ./pkg/builder

# Run tests with data race detection
go test -race ./...

# Format and vet
go fmt ./... && go vet ./...

# Local production binary build (CGO disabled, stripped symbols)
CGO_ENABLED=0 go build -trimpath -ldflags "-w -s" -o sub2sfm main.go

# Docker container build and run
docker build -t sub2sfm .
docker compose up -d --build
```

## Code Conventions & Common Patterns

### Formatting & Style
- **Go Version**: Go 1.27 (`go.mod`), formatted strictly with standard `gofmt` (tabs).
- **Naming**: Exported identifiers use PascalCase (`BuildSingBoxConfig`, `ParseTrojanURI`); unexported helpers use camelCase (`parseOptions`, `getEnv`). Comment all exported symbols.
- **Dependency Philosophy**: Standard library first. Only one external runtime dependency is permitted: `gopkg.in/yaml.v3` (for Clash YAML parsing).

### Config Construction Pattern
- Sing-box configuration trees MUST be assembled as AST-like nested `map[string]any` dictionaries and serialized using `json.MarshalIndent`.
- **Never** use raw string concatenation or text templates to build Sing-box configurations.

### Error Handling
- Wrap errors with actionable context using `fmt.Errorf("context: %w", err)`.
- HTTP handlers convert internal errors into appropriate HTTP error codes (`400 Bad Request` for invalid input parameters; `502 Bad Gateway` for upstream fetch failures).

### Concurrency & State Management
- Stateless HTTP request handling; concurrency is isolated per request.
- Remote subscriptions are cached in `pkg/parser/cache.go` using a thread-safe `SubscriptionCache` backed by `sync.RWMutex` with a 5-minute TTL.
- Honor `context.Context` cancellation and timeouts in HTTP calls (`FetchSubscription`).
- Process lifecycle in `main.go` uses `os/signal` to handle `SIGINT` and `SIGTERM` with a 5-second graceful shutdown timeout.

### Sing-box v1.12+ Schema Constraints & Gotchas
- **Inbounds**: Do NOT use deprecated `inet4_address` or `inet6_address`. Do NOT put `sniff: true` directly on inbounds; sniffing belongs under `route.rules` as `{"inbound": ["tun-in"], "action": "sniff"}`.
- **DNS Rules**:
  - `dns_direct` **must never** have `detour: 全局直连` or point to an empty direct outbound (causes Sing-box startup panic: *"detour to an empty direct outbound makes no sense"*).
  - Never emit `action: resolve` in DNS rules (leaks Fake-IP hostnames).
  - `geosite-cn` rules must be evaluated before Fake-IP to avoid domestic DNS contamination.
- **Outbound Tags**:
  - Outbound tags colliding with reserved selector names (`节点选择`, `自动选择`, `全局直连`, `全局拦截`, `SSH出口`, `WebRTC防护`, `AI服务`, `开发服务`) must be disambiguated with numeric suffixes (e.g., `节点选择 (2)`).

## Important Files

| File | Purpose |
|---|---|
| `main.go` | CLI flag parsing (`-host`, `-port`), env var fallbacks (`HOST`, `PORT`), structured logging (`slog`), and graceful shutdown. |
| `pkg/model/node.go` | Canonical `Node` struct and `ConvertOptions` parameter settings. |
| `pkg/server/handler.go` | HTTP routing (`/`, `/health`, `/sub`, `/api/convert`), embedded UI, parameter parsing. |
| `pkg/server/static/index.html` | Zero-dependency, self-contained embedded Web UI for interactive configuration generation. |
| `pkg/parser/parser.go` | Sub format auto-detection engine and upstream HTTP fetcher with custom UA and insecure TLS transport. |
| `pkg/parser/cache.go` | In-memory thread-safe 5-minute TTL subscription cache with cache-busting purge hooks. |
| `pkg/parser/clash.go` | Parser converting Clash / Clash.Meta YAML proxies into `*model.Node` slices. |
| `pkg/parser/trojan.go` | Parsers for `trojan://`, `vless://`, `hysteria2://`/`hy2://`, `ss://` URIs, and Base64 decoders. |
| `pkg/builder/builder.go` | Root Sing-box configuration compiler uniting inbounds, DNS, outbounds, route, and experimental options. |
| `pkg/builder/tun.go` | TUN and Mixed inbounds setup (`stack: mixed`, `mtu: 1500`, port 2080). |
| `pkg/builder/dns.go` | Sing-box 1.12+ DNS hierarchy, anti-leak rule sequencing, and Type 65 blocking. |
| `pkg/builder/outbounds.go` | System selectors generation, tag deduplication, and protocol outbound generators. |
| `pkg/builder/route.go` | Sniffing, DNS hijack, STUN leak blocking, presets (`geek`, `standard`, `global`), custom rule DSL, and remote rule-sets. |
| `Dockerfile` & `compose.yml` | Multi-stage scratch/Alpine build, non-root execution (`nobody:nobody`), port 8080. |

## Runtime/Tooling Preferences

- **Go Runtime**: Go 1.27+ toolchain (`1.27.3` specified in `go.mod`, compatible with Go 1.23+).
- **Package Manager**: Go Modules (`go.mod`, `go.sum`).
- **Binary Footprint**: Compile statically with `CGO_ENABLED=0`, `-trimpath`, and `-ldflags "-w -s"`.
- **Static Assets**: Embedded at compile time via `//go:embed static/index.html` in `pkg/server/handler.go`. No Node.js, Bun, npm, or frontend bundlers needed.
- **Logging**: Standard library `log/slog` outputting structured plain text to `os.Stdout`.
- **Container Environment**: Runs on Alpine as `USER nobody` with exposed port `8080`.

## Testing & QA

- **Frameworks**: Standard library `testing` and `net/http/httptest`. No third-party assertion or mock frameworks.
- **Hermetic Testing**: All tests must be 100% in-memory with zero outbound network calls.
  - Remote subscription endpoints must be mocked using `httptest.NewServer`.
  - Cache entries in tests must be cleaned up via `defer PurgeSubscriptionCache(ts.URL)`.
- **JSON Structure Assertions**:
  - Always unmarshal generated Sing-box JSON into `map[string]any` to verify fields, values, and array sequences.
  - Avoid fragile raw string comparisons on generated JSON (which fail on whitespace or non-deterministic key ordering).
  - Explicitly test for the absence of deprecated or leak-prone fields (e.g., `inet4_address`, `fakeip` under dns, `action: resolve`).
- **Test Co-location**: Unit tests reside next to implementation files (`main_test.go`, `*_test.go` in each `pkg/` subdirectory).

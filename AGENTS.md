# Repository Guidelines

`sub2sfm` is a single-binary Go service. It turns airport subscriptions (Clash YAML, Base64, or URIs for Trojan, VLESS Reality, Hysteria 2, Shadowsocks, and VMess) into Sing-box JSON for macOS SFM.

## Project Structure & Module Organization

- `main.go` — `-host` / `-port`, `slog`, graceful shutdown.
- `pkg/model/` — `Node` and `ConvertOptions`.
- `pkg/parser/` — fetch and parse (`parser.go`, `clash.go`, `trojan.go`, `cache.go`).
- `pkg/builder/` — Sing-box JSON (`tun.go`, `dns.go`, `outbounds.go`, `route.go`, `builder.go`).
- `pkg/server/` — `GET /`, `GET /health`, `GET /sub`, `POST /api/convert`. UI: `pkg/server/static/index.html` via `//go:embed`.
- `Dockerfile`, `compose.yml` — Alpine image on port 8080.

Tests sit beside the code: `main_test.go`, `pkg/parser/parser_test.go`, `pkg/builder/builder_test.go`, `pkg/server/handler_test.go`.

## Build, Test, and Development Commands

```bash
go run main.go -port 8080          # http://127.0.0.1:8080
go build -o sub2sfm main.go   # local binary
go test ./...                      # all unit tests
go test -cover ./...               # coverage summary
go fmt ./... && go vet ./...       # format and vet
docker compose up -d --build       # container on :8080
```

`HOST` and `PORT` override the listen address. Image builds set `CGO_ENABLED=0`.

## Coding Style & Naming Conventions

Module `sub2sfm`, Go 1.27. Format with `gofmt` (tabs). Exported names are PascalCase (`BuildSingBoxConfig`, `ParseTrojanURI`); unexported helpers are camelCase (`parseOptions`, `getEnv`). Comment exported symbols. Prefer the standard library; the only module dependency is `gopkg.in/yaml.v3`. Build configs as `map[string]any` and marshal with `json.MarshalIndent`. Wrap errors with `fmt.Errorf("context: %w", err)`.

## Testing Guidelines

Use `testing` and `net/http/httptest`. Name tests `TestFunction` or `TestType_Behavior`, for example `TestBuildSingBoxConfig_IPv6Option`. Assert JSON fields (TUN `stack`/`mtu`, DNS rule order, TLS `insecure`), not raw text. Each new parser format, query option, or route rule needs a case in that package’s `*_test.go`. Keep tests in memory with no network.

## Commit & Pull Request Guidelines

History uses Conventional Commits: `feat:` or `chore:`, an imperative subject, then a body that states the behavior change. Example: `feat: disable IPv6 by default and stop DNS detour to empty direct`. Pull requests should say what changed for SFM users, list commands run (`go test ./...`), and link an issue when one exists. Add a screenshot only when `pkg/server/static/index.html` changes.

## Security & Configuration Tips

Do not commit airport URLs, node passwords, or generated configs. Log lengths and errors, not subscription bodies. `FetchSubscription` skips TLS verification for airport certificates; do not reuse that client. The container runs as `nobody`. Keep `geosite-cn` ahead of Fake-IP, and leave out `action: resolve`.

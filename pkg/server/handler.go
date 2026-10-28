package server

import (
	_ "embed"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sub2sfm/pkg/builder"
	"sub2sfm/pkg/model"
	"sub2sfm/pkg/parser"
)

//go:embed static/index.html
var indexHTML []byte

// Handler 包装 Web 与 API 路由处理器
type Handler struct {
	logger *slog.Logger
}

// NewHandler 创建服务处理器
func NewHandler(logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{logger: logger}
}

// RegisterRoutes 注册路由到 http.ServeMux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.handleIndex)
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /sub", h.handleSub)
	mux.HandleFunc("POST /api/convert", h.handleConvert)
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexHTML)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleSub(w http.ResponseWriter, r *http.Request) {
	subInput := strings.TrimSpace(r.URL.Query().Get("sub"))
	if subInput == "" {
		subInput = strings.TrimSpace(r.URL.Query().Get("url"))
	}
	if subInput == "" {
		http.Error(w, "missing required query parameter: sub", http.StatusBadRequest)
		return
	}

	if isTrueParam(r.URL.Query().Get("refresh")) || isTrueParam(r.URL.Query().Get("nocache")) {
		parser.PurgeSubscriptionCache(subInput)
	}

	opts := parseOptions(r)
	nodes, err := parser.ParseFromInput(r.Context(), subInput)
	if err != nil {
		h.logger.Error("failed to parse subscription", "error", err, "input_len", len(subInput))
		http.Error(w, "failed to parse subscription: "+err.Error(), http.StatusBadGateway)
		return
	}

	configJSON, err := builder.BuildSingBoxConfig(nodes, opts)
	if err != nil {
		h.logger.Error("failed to build sing-box config", "error", err)
		http.Error(w, "failed to build config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="singbox.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(configJSON)
}

func (h *Handler) handleConvert(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "empty request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	opts := parseOptions(r)

	nodes, err := parser.Parse(body)
	if err != nil {
		http.Error(w, "parse failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	configJSON, err := builder.BuildSingBoxConfig(nodes, opts)
	if err != nil {
		http.Error(w, "build failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(configJSON)
}

// Router 返回包装好路由的 http.Handler
func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

func parseOptions(r *http.Request) model.ConvertOptions {
	q := r.URL.Query()
	return model.ConvertOptions{
		Preset:        q.Get("preset"),
		SSHMode:       q.Get("ssh"),
		WebRTCMode:    q.Get("webrtc"),
		CustomRules:   q.Get("rules"),
		AllowInsecure: isTrueParam(q.Get("insecure")) || isTrueParam(q.Get("allow_insecure")) || isTrueParam(q.Get("skip_cert_verify")),
		EnableIPv6:    isTrueParam(q.Get("ipv6")),
		RuleCDN:       isTrueParam(q.Get("cdn")) || isTrueParam(q.Get("rule_cdn")),
	}
}

func isTrueParam(val string) bool {
	return strings.EqualFold(val, "true") || strings.EqualFold(val, "on") || val == "1"
}

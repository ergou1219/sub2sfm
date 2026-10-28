package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHandler_IndexAndHealth(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()

	// 1. Test /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 on /, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sub2sfm · 机场订阅转 Sing-box") {
		t.Errorf("index html does not contain expected title")
	}
	if !strings.Contains(rec.Body.String(), "allowInsecure") {
		t.Errorf("index html does not contain allowInsecure checkbox")
	}
	if !strings.Contains(rec.Body.String(), "ipv6Off") {
		t.Errorf("index html does not contain ipv6Off checkbox")
	}
	if !strings.Contains(rec.Body.String(), `id="ruleCdn"`) {
		t.Errorf("index html does not contain ruleCdn checkbox")
	}
	if !strings.Contains(rec.Body.String(), "规则走 CDN") {
		t.Errorf("index html does not contain 规则走 CDN label")
	}

	// 2. Test /health
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 on /health, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("unexpected health body: %s", rec.Body.String())
	}
}

func TestHandler_SubEndpoint(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()

	// 1. Missing sub
	req := httptest.NewRequest(http.MethodGet, "/sub", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on missing sub, got %d", rec.Code)
	}

	// 2. Valid raw trojan URI in sub param
	trojanURI := "trojan://testpwd@hk.test.com:443#HongKongTest"
	u := "/sub?sub=" + url.QueryEscape(trojanURI) + "&preset=geek&ssh=direct"
	req = httptest.NewRequest(http.MethodGet, u, nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /sub, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatalf("invalid json returned from /sub: %v", err)
	}
	if root["inbounds"] == nil || root["outbounds"] == nil {
		t.Errorf("missing core fields in generated json")
	}
}

func TestHandler_ConvertAPI(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()

	clashYaml := `
proxies:
  - name: "SG 01"
    type: trojan
    server: sg.test.com
    port: 443
    password: "pwd"
`
	req := httptest.NewRequest(http.MethodPost, "/api/convert", strings.NewReader(clashYaml))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/convert, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatalf("invalid json returned: %v", err)
	}
}

func TestHandler_InsecureParams(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()
	trojanURI := "trojan://testpwd@hk.test.com:443#HongKongTest"

	checkInsecure := func(u string, expected bool) {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request to %s failed: %d", u, rec.Code)
		}
		var root map[string]any
		json.Unmarshal(rec.Body.Bytes(), &root)
		outbounds := root["outbounds"].([]any)
		found := false
		for _, oAny := range outbounds {
			o := oAny.(map[string]any)
			if o["tag"] == "HongKongTest" {
				found = true
				tls := o["tls"].(map[string]any)
				if tls["insecure"] != expected {
					t.Errorf("url %s: expected tls.insecure=%v, got %v", u, expected, tls["insecure"])
				}
			}
		}
		if !found {
			t.Errorf("url %s: node HongKongTest not found", u)
		}
	}

	// 1. Default (no insecure param) -> false
	checkInsecure("/sub?sub="+url.QueryEscape(trojanURI), false)
	// 2. insecure=true -> true
	checkInsecure("/sub?sub="+url.QueryEscape(trojanURI)+"&insecure=true", true)
	// 3. allow_insecure=1 -> true
	checkInsecure("/sub?sub="+url.QueryEscape(trojanURI)+"&allow_insecure=1", true)
	// 4. skip_cert_verify=true -> true
	checkInsecure("/sub?sub="+url.QueryEscape(trojanURI)+"&skip_cert_verify=true", true)
}

func TestHandler_IPv6Param(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()
	trojanURI := "trojan://testpwd@hk.test.com:443#HongKongTest"

	check := func(u string, wantIPv6 bool, wantStrategy string) {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request to %s failed: %d", u, rec.Code)
		}
		var root map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
			t.Fatalf("invalid json from %s: %v", u, err)
		}
		tun := root["inbounds"].([]any)[0].(map[string]any)
		addresses := tun["address"].([]any)
		if got := len(addresses) == 2; got != wantIPv6 {
			t.Errorf("url %s: expected dual-stack=%v, got address %v", u, wantIPv6, addresses)
		}
		if dns := root["dns"].(map[string]any); dns["strategy"] != wantStrategy {
			t.Errorf("url %s: expected dns strategy %q, got %v", u, wantStrategy, dns["strategy"])
		}
	}

	base := "/sub?sub=" + url.QueryEscape(trojanURI)
	check(base, false, "ipv4_only")
	check(base+"&ipv6=off", false, "ipv4_only")
	check(base+"&ipv6=on", true, "prefer_ipv4")
}

func TestHandler_SubEndpoint_MixedProtocolsAndRefresh(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()

	mixed := "vless://11111111-2222-3333-4444-555555555555@vless.com:443#SameTag\nhy2://pwd@hy2.com:8443#SameTag\n"
	req := httptest.NewRequest(http.MethodGet, "/sub?sub="+url.QueryEscape(mixed)+"&refresh=1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	outbounds := root["outbounds"].([]any)
	foundVless := false
	foundHy2 := false
	for _, ob := range outbounds {
		m := ob.(map[string]any)
		if m["tag"] == "SameTag" && m["type"] == "vless" {
			foundVless = true
		}
		if m["tag"] == "SameTag (2)" && m["type"] == "hysteria2" {
			foundHy2 = true
		}
	}
	if !foundVless || !foundHy2 {
		t.Errorf("expected deduplicated outbounds, foundVless=%v, foundHy2=%v", foundVless, foundHy2)
	}
}

func TestHandler_SubEndpoint_WhitespaceAndNoCache(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()

	trojanURI := "  trojan://testpwd@hk.test.com:443#HongKongWhitespace  \n"
	req := httptest.NewRequest(http.MethodGet, "/sub?sub="+url.QueryEscape(trojanURI)+"&nocache=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	outbounds := root["outbounds"].([]any)
	found := false
	for _, ob := range outbounds {
		m := ob.(map[string]any)
		if m["tag"] == "HongKongWhitespace" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find HongKongWhitespace outbound in response")
	}
}

func TestHandler_CDNParam(t *testing.T) {
	h := NewHandler(nil)
	mux := h.Router()
	trojanURI := "trojan://testpwd@hk.test.com:443#HongKongCDN"

	checkCDN := func(u string, wantCDN bool) {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request to %s failed: %d", u, rec.Code)
		}
		var root map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		route, ok := root["route"].(map[string]any)
		if !ok {
			t.Fatalf("missing route in json")
		}
		ruleSets, ok := route["rule_set"].([]any)
		if !ok || len(ruleSets) == 0 {
			t.Fatalf("missing rule_set in route")
		}
		prefix := "https://raw.githubusercontent.com/SagerNet/"
		if wantCDN {
			prefix = "https://cdn.jsdelivr.net/gh/SagerNet/"
		}
		for _, rsAny := range ruleSets {
			rs := rsAny.(map[string]any)
			urlStr, _ := rs["url"].(string)
			if !strings.HasPrefix(urlStr, prefix) {
				t.Errorf("url %s: expected prefix %s, got %s", u, prefix, urlStr)
			}
		}
	}

	base := "/sub?sub=" + url.QueryEscape(trojanURI)
	checkCDN(base, false)
	checkCDN(base+"&cdn=true", true)
	checkCDN(base+"&cdn=1", true)
	checkCDN(base+"&rule_cdn=1", true)
}

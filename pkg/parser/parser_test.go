package parser

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTrojanURI(t *testing.T) {
	uri := "trojan://mypassword@hk.server.com:443?sni=hk.server.com&allowInsecure=1&type=ws&host=ws.server.com&path=%2Ftrojan-ws#%E9%A6%99%E6%B8%AF%2001"
	node, err := ParseTrojanURI(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if node.Tag != "香港 01" {
		t.Errorf("expected Tag '香港 01', got %q", node.Tag)
	}
	if node.Password != "mypassword" {
		t.Errorf("expected Password 'mypassword', got %q", node.Password)
	}
	if node.Server != "hk.server.com" {
		t.Errorf("expected Server 'hk.server.com', got %q", node.Server)
	}
	if node.Port != 443 {
		t.Errorf("expected Port 443, got %d", node.Port)
	}
	if node.SNI != "hk.server.com" {
		t.Errorf("expected SNI 'hk.server.com', got %q", node.SNI)
	}
	if !node.SkipCertVerify {
		t.Errorf("expected SkipCertVerify true")
	}
	if node.Network != "ws" {
		t.Errorf("expected Network 'ws', got %q", node.Network)
	}
	if node.WSPath != "/trojan-ws" {
		t.Errorf("expected WSPath '/trojan-ws', got %q", node.WSPath)
	}
	if node.WSHeaders["Host"] != "ws.server.com" {
		t.Errorf("expected WSHeaders[Host] 'ws.server.com', got %v", node.WSHeaders)
	}
}

func TestParseClashYAML(t *testing.T) {
	clashData := `
proxies:
  - name: "日本 01"
    type: trojan
    server: jp.example.com
    port: 443
    password: "secret_password"
    sni: jp.example.com
    skip-cert-verify: false
    udp: true
    network: ws
    ws-opts:
      path: /ws-path
      headers:
        Host: jp.example.com
  - name: "美国 01"
    type: trojan
    server: us.example.com
    port: 8443
    password: "secret_password"
    udp: true
`
	nodes, err := ParseClashYAML([]byte(clashData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	n1 := nodes[0]
	if n1.Tag != "日本 01" || n1.Server != "jp.example.com" || n1.WSPath != "/ws-path" {
		t.Errorf("unexpected node 1 data: %+v", n1)
	}

	n2 := nodes[1]
	if n2.Tag != "美国 01" || n2.Port != 8443 || n2.SNI != "us.example.com" {
		t.Errorf("unexpected node 2 data: %+v", n2)
	}
}

func TestParseAutoDetection(t *testing.T) {
	// 1. Raw Trojan links
	rawLinks := "trojan://pwd1@hk1.com:443#HK1\ntrojan://pwd2@hk2.com:443#HK2"
	nodes, err := Parse([]byte(rawLinks))
	if err != nil || len(nodes) != 2 {
		t.Fatalf("failed parsing raw links: %v", err)
	}

	// 2. Base64 encoded Trojan links
	b64 := base64.StdEncoding.EncodeToString([]byte(rawLinks))
	nodes, err = Parse([]byte(b64))
	if err != nil || len(nodes) != 2 {
		t.Fatalf("failed parsing base64 links: %v", err)
	}

	// 3. Clash YAML
	clashYaml := `
proxies:
  - name: "SGP"
    type: trojan
    server: sgp.com
    port: 443
    password: "pwd"
`
	nodes, err = Parse([]byte(clashYaml))
	if err != nil || len(nodes) != 1 {
		t.Fatalf("failed parsing clash yaml: %v", err)
	}
}

func TestFetchSubscription_CacheAndPurge(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_, _ = w.Write([]byte("trojan://pwd@server.com:443#cached-node\n"))
	}))
	defer ts.Close()

	defer PurgeSubscriptionCache(ts.URL)

	// 1. Initial fetch
	data1, err := FetchSubscription(context.Background(), ts.URL, "")
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 upstream call, got %d", callCount)
	}

	// 2. Shut down upstream server
	ts.Close()

	// 3. Second fetch should hit cache despite server being down
	data2, err := FetchSubscription(context.Background(), ts.URL, "")
	if err != nil {
		t.Fatalf("second fetch from cache failed: %v", err)
	}
	if string(data1) != string(data2) {
		t.Fatalf("cached data mismatch")
	}

	// 4. Purge cache and fetch again -> should fail now
	PurgeSubscriptionCache(ts.URL)
	_, err = FetchSubscription(context.Background(), ts.URL, "")
	if err == nil {
		t.Fatalf("expected error after cache purge with server closed, got nil")
	}
}

func TestParseVlessURI(t *testing.T) {
	uri := "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?security=reality&sni=sni.example.com&pbk=my_pubkey&sid=my_shortid&flow=xtls-rprx-vision&type=tcp&alpn=h2,http/1.1#%E9%A6%99%E6%B8%AF-VLESS"
	node, err := ParseVlessURI(uri)
	if err != nil {
		t.Fatalf("ParseVlessURI failed: %v", err)
	}
	if node.Tag != "香港-VLESS" {
		t.Errorf("expected tag '香港-VLESS', got %q", node.Tag)
	}
	if node.Type != "vless" {
		t.Errorf("expected type 'vless', got %q", node.Type)
	}
	if node.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("expected UUID, got %q", node.UUID)
	}
	if node.RealityPubKey != "my_pubkey" || node.RealityShortID != "my_shortid" {
		t.Errorf("unexpected reality opts: pbk=%q, sid=%q", node.RealityPubKey, node.RealityShortID)
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Errorf("expected flow 'xtls-rprx-vision', got %q", node.Flow)
	}
	if len(node.ALPN) != 2 || node.ALPN[0] != "h2" || node.ALPN[1] != "http/1.1" {
		t.Errorf("expected ALPN [h2, http/1.1], got %v", node.ALPN)
	}
}

func TestParseHysteria2URI(t *testing.T) {
	uri := "hysteria2://my_secret_pass@hy2.example.com:8443?sni=sni.hy2.com&insecure=1&obfs=salamander&obfs-password=obfspwd#%E6%97%A5%E6%9C%AC-HY2"
	node, err := ParseHysteria2URI(uri)
	if err != nil {
		t.Fatalf("ParseHysteria2URI failed: %v", err)
	}
	if node.Tag != "日本-HY2" {
		t.Errorf("expected tag '日本-HY2', got %q", node.Tag)
	}
	if node.Type != "hysteria2" {
		t.Errorf("expected type 'hysteria2', got %q", node.Type)
	}
	if node.Password != "my_secret_pass" {
		t.Errorf("expected password 'my_secret_pass', got %q", node.Password)
	}
	if !node.SkipCertVerify {
		t.Errorf("expected SkipCertVerify true")
	}
	if node.ObfsType != "salamander" || node.ObfsPassword != "obfspwd" {
		t.Errorf("unexpected obfs: type=%q, pwd=%q", node.ObfsType, node.ObfsPassword)
	}
}

func TestParseShadowsocksURI(t *testing.T) {
	// SIP002: ss://base64(method:password)@host:port#tag
	userBase64 := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:sspassword"))
	uri1 := "ss://" + userBase64 + "@ss.example.com:8388#%E6%96%B0%E5%8A%A0%E5%9D%A1-SS"
	node1, err := ParseShadowsocksURI(uri1)
	if err != nil {
		t.Fatalf("ParseShadowsocksURI SIP002 failed: %v", err)
	}
	if node1.Tag != "新加坡-SS" || node1.Method != "aes-256-gcm" || node1.Password != "sspassword" || node1.Port != 8388 {
		t.Errorf("unexpected node1: %+v", node1)
	}

	// Legacy: ss://base64(method:password@host:port)#tag
	legacyBase64 := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:legacy_pwd@ss2.example.com:9000"))
	uri2 := "ss://" + legacyBase64 + "#Legacy-SS"
	node2, err := ParseShadowsocksURI(uri2)
	if err != nil {
		t.Fatalf("ParseShadowsocksURI legacy failed: %v", err)
	}
	if node2.Tag != "Legacy-SS" || node2.Method != "chacha20-ietf-poly1305" || node2.Password != "legacy_pwd" || node2.Port != 9000 {
		t.Errorf("unexpected node2: %+v", node2)
	}
}

func TestParseClashYAML_MultiProtocol(t *testing.T) {
	clashData := `
proxies:
  - name: "Trojan Node"
    type: trojan
    server: trojan.com
    port: 443
    password: "pwd"
  - name: "Vless Reality Node"
    type: vless
    server: vless.com
    port: 443
    uuid: "11111111-2222-3333-4444-555555555555"
    flow: "xtls-rprx-vision"
    reality-opts:
      public-key: "pubkey123"
      short-id: "shortid123"
  - name: "Hysteria2 Node"
    type: hysteria2
    server: hy2.com
    port: 8443
    password: "hy2pwd"
    obfs: salamander
    obfs-password: "obfspassword"
  - name: "Shadowsocks Node"
    type: ss
    server: ss.com
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: "sspassword"
  - name: "VMess Node"
    type: vmess
    server: vmess.com
    port: 443
    uuid: "22222222-3333-4444-5555-666666666666"
    alterId: 0
`
	nodes, err := ParseClashYAML([]byte(clashData))
	if err != nil {
		t.Fatalf("ParseClashYAML failed: %v", err)
	}
	if len(nodes) != 5 {
		t.Fatalf("expected 5 nodes, got %d", len(nodes))
	}
	if nodes[0].Type != "trojan" || nodes[1].Type != "vless" || nodes[2].Type != "hysteria2" || nodes[3].Type != "shadowsocks" || nodes[4].Type != "vmess" {
		t.Fatalf("unexpected node types: %v, %v, %v, %v, %v", nodes[0].Type, nodes[1].Type, nodes[2].Type, nodes[3].Type, nodes[4].Type)
	}
	if nodes[1].RealityPubKey != "pubkey123" {
		t.Errorf("expected RealityPubKey 'pubkey123', got %q", nodes[1].RealityPubKey)
	}
	if nodes[3].Method != "2022-blake3-aes-128-gcm" {
		t.Errorf("expected Method '2022-blake3-aes-128-gcm', got %q", nodes[3].Method)
	}
}

func TestParseAutoDetection_MultiProtocolLines(t *testing.T) {
	lines := `
vless://11111111-2222-3333-4444-555555555555@vless.com:443#VLESS-Node
hy2://pwd@hy2.com:8443#HY2-Node
`
	b64 := base64.StdEncoding.EncodeToString([]byte(lines))
	nodes, err := Parse([]byte(b64))
	if err != nil {
		t.Fatalf("Parse b64 lines failed: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Type != "vless" || nodes[1].Type != "hysteria2" {
		t.Errorf("unexpected types: %s, %s", nodes[0].Type, nodes[1].Type)
	}
}

func TestParseShadowsocksURI_TrailingSlashAndAtInPassword(t *testing.T) {
	// SIP002 with trailing slash before fragment
	sip002 := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388/#%E6%B5%8B%E8%AF%95"
	node, err := ParseShadowsocksURI(sip002)
	if err != nil {
		t.Fatalf("ParseShadowsocksURI sip002 failed: %v", err)
	}
	if node.Server != "1.2.3.4" || node.Port != 8388 {
		t.Errorf("sip002 server/port mismatch: %s:%d", node.Server, node.Port)
	}

	// Legacy base64 with '@' in password
	payload := "aes-128-gcm:my@secret@pwd@1.2.3.4:8388"
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte(payload)) + "#Legacy"
	node2, err := ParseShadowsocksURI(legacy)
	if err != nil {
		t.Fatalf("ParseShadowsocksURI legacy with @ failed: %v", err)
	}
	if node2.Password != "my@secret@pwd" || node2.Server != "1.2.3.4" || node2.Port != 8388 {
		t.Errorf("legacy password/server/port mismatch: pass=%s, server=%s, port=%d", node2.Password, node2.Server, node2.Port)
	}
}

func TestParseClashYAML_VMessNon443TLS(t *testing.T) {
	clashData := `
proxies:
  - name: "VMess Non-443 TLS"
    type: vmess
    server: vmess.custom.com
    port: 8443
    uuid: "22222222-3333-4444-5555-666666666666"
    alterId: 0
    tls: true
`
	nodes, err := ParseClashYAML([]byte(clashData))
	if err != nil {
		t.Fatalf("ParseClashYAML failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].SNI != "vmess.custom.com" {
		t.Errorf("expected SNI fallback to server 'vmess.custom.com', got %q", nodes[0].SNI)
	}
}

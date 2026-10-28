package builder

import (
	"encoding/json"
	"strings"
	"testing"

	"sub2sfm/pkg/model"
)

func sampleNodes() []*model.Node {
	return []*model.Node{
		{
			Tag:      "香港 01",
			Type:     "trojan",
			Server:   "hk1.example.com",
			Port:     443,
			Password: "pwd1",
			SNI:      "hk1.example.com",
			Network:  "tcp",
		},
		{
			Tag:            "日本 01",
			Type:           "trojan",
			Server:         "jp1.example.com",
			Port:           8443,
			Password:       "pwd2",
			SNI:            "jp1.example.com",
			SkipCertVerify: true,
			Network:        "ws",
			WSPath:         "/ws",
			WSHeaders:      map[string]string{"Host": "jp1.example.com"},
		},
	}
}

func TestBuildSingBoxConfig_CoreRequirements(t *testing.T) {
	opts := model.ConvertOptions{
		Preset:      "geek",
		SSHMode:     "direct",
		WebRTCMode:  "block",
		CustomRules: "domain:custom-work.internal=direct,port:2222=SSH出口,domain:blocked.example=block",
	}

	configJSON, err := BuildSingBoxConfig(sampleNodes(), opts)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		t.Fatalf("failed to unmarshal generated json: %v", err)
	}

	// 1. 验证 TUN 入站核心参数（防断连）
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		t.Fatalf("inbounds missing or empty")
	}
	tun := inbounds[0].(map[string]any)
	if tun["type"] != "tun" {
		t.Errorf("expected inbound type 'tun', got %v", tun["type"])
	}
	if tun["stack"] != "mixed" {
		t.Errorf("expected tun stack 'mixed', got %v", tun["stack"])
	}
	if tun["mtu"] != float64(1500) {
		t.Errorf("expected tun mtu 1500, got %v", tun["mtu"])
	}
	if tun["auto_route"] != true || tun["strict_route"] != true {
		t.Errorf("expected auto_route and strict_route to be true")
	}
	addresses, ok := tun["address"].([]any)
	if !ok || len(addresses) != 1 || addresses[0] != "172.19.0.1/30" {
		t.Errorf("expected IPv4-only tun address by default, got %v", tun["address"])
	}
	if _, ok := tun["inet4_address"]; ok {
		t.Errorf("legacy tun inet4_address must not be used")
	}
	if _, ok := tun["inet6_address"]; ok {
		t.Errorf("legacy tun inet6_address must not be used")
	}
	if _, ok := tun["sniff"]; ok {
		t.Errorf("legacy tun sniff field must not be used")
	}

	// 2. 验证 DNS 分流与防泄漏（geosite-cn 必须排在 fakeip 前面，且绝对不能有 action: resolve）
	dns := root["dns"].(map[string]any)
	if s, _ := dns["strategy"].(string); s != "ipv4_only" {
		t.Errorf("dns strategy must be ipv4_only: direct AAAA is served for CN domains, but the TUN's broken IPv6 path makes clients (Chrome) fail without falling back to IPv4 (got %q)", s)
	}
	dnsRules := dns["rules"].([]any)
	fakeipIdx := -1
	geositeCnIdx := -1

	for idx, rAny := range dnsRules {
		r := rAny.(map[string]any)
		if s, ok := r["server"].(string); ok && s == "dns_fakeip" {
			fakeipIdx = idx
		}
		if rs, ok := r["rule_set"].([]any); ok {
			for _, item := range rs {
				if item.(string) == "geosite-cn" {
					geositeCnIdx = idx
				}
			}
		}
	}

	if geositeCnIdx == -1 {
		t.Errorf("geosite-cn rule not found in DNS rules")
	}
	if fakeipIdx == -1 {
		t.Errorf("fakeip rule not found in DNS rules")
	}
	if geositeCnIdx >= fakeipIdx {
		t.Errorf("DNS leak risk: geosite-cn (%d) should be ordered BEFORE fakeip (%d)", geositeCnIdx, fakeipIdx)
	}

	// 3. 验证路由规则
	route := root["route"].(map[string]any)
	routeRules := route["rules"].([]any)

	hasSSH := false
	hasSniff := false
	hasWebRTCBlock := false
	hasCustomDomain := false
	hasCustomPort := false
	hasCustomBlock := false
	hasActionResolve := false

	for _, rAny := range routeRules {
		r := rAny.(map[string]any)
		action, _ := r["action"].(string)
		if action == "resolve" {
			hasActionResolve = true
		}
		if action == "sniff" {
			hasSniff = true
		}
		if outbound, ok := r["outbound"].(string); ok {
			if outbound == "SSH出口" {
				if ports, ok := r["port"].([]any); ok {
					for _, p := range ports {
						if p.(float64) == 22 {
							hasSSH = true
						}
						if p.(float64) == 2222 {
							hasCustomPort = true
						}
					}
				}
			}
			if outbound == "WebRTC防护" && r["protocol"] == "stun" {
				hasWebRTCBlock = true
			}
			if outbound == "全局直连" {
				if doms, ok := r["domain"].([]any); ok {
					for _, d := range doms {
						if d.(string) == "custom-work.internal" {
							hasCustomDomain = true
						}
					}
				}
			}
			if outbound == "全局拦截" {
				if doms, ok := r["domain"].([]any); ok {
					for _, d := range doms {
						if d.(string) == "blocked.example" {
							hasCustomBlock = true
						}
					}
				}
			}
		}
	}

	if !hasSSH {
		t.Errorf("SSH rule (port 22 -> SSH出口) not found in route rules")
	}
	if !hasSniff {
		t.Errorf("sniff action for tun-in not found in route rules")
	}
	if !hasWebRTCBlock {
		t.Errorf("WebRTC rule (stun -> WebRTC防护) not found in route rules")
	}
	if !hasCustomDomain {
		t.Errorf("custom domain rule not found in route rules")
	}
	if !hasCustomPort {
		t.Errorf("custom port rule not found in route rules")
	}
	if !hasCustomBlock {
		t.Errorf("custom block rule not found in route rules")
	}
	if hasActionResolve {
		t.Errorf("DNS leak risk: route rules should NOT contain 'action: resolve'")
	}

	// 4. 验证出站策略组配置
	outbounds := root["outbounds"].([]any)
	groupMap := make(map[string]map[string]any)
	for _, oAny := range outbounds {
		o := oAny.(map[string]any)
		if tag, ok := o["tag"].(string); ok {
			groupMap[tag] = o
		}
	}

	if _, ok := groupMap["SSH出口"]; !ok {
		t.Errorf("group 'SSH出口' not found in outbounds")
	}
	if groupMap["SSH出口"]["default"] != "全局直连" {
		t.Errorf("expected default SSH出口 '全局直连', got %v", groupMap["SSH出口"]["default"])
	}
	if groupMap["WebRTC防护"]["default"] != "全局拦截" {
		t.Errorf("expected WebRTC防护 default '全局拦截', got %v", groupMap["WebRTC防护"]["default"])
	}
	if groupMap["全局拦截"]["type"] != "block" {
		t.Errorf("expected 全局拦截 outbound type 'block', got %v", groupMap["全局拦截"]["type"])
	}
	for _, o := range groupMap {
		if o["type"] == "dns" {
			t.Errorf("legacy outbound type %v must not be used", o["type"])
		}
	}
	if _, ok := groupMap["AI服务"]; !ok {
		t.Errorf("group 'AI服务' not found in geek preset")
	}
	if _, ok := groupMap["开发服务"]; !ok {
		t.Errorf("group '开发服务' not found in geek preset")
	}
}

func TestBuildSingBoxConfig_DNSNewServerFormat(t *testing.T) {
	configJSON, err := BuildSingBoxConfig(sampleNodes(), model.ConvertOptions{Preset: "geek"})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		t.Fatalf("failed to unmarshal generated json: %v", err)
	}

	dns := root["dns"].(map[string]any)

	// 新格式不再使用顶层 dns.fakeip 与 independent_cache
	if _, ok := dns["fakeip"]; ok {
		t.Errorf("legacy dns.fakeip must not be used")
	}
	if _, ok := dns["independent_cache"]; ok {
		t.Errorf("deprecated dns.independent_cache must not be used")
	}

	servers := dns["servers"].([]any)
	fakeipFound := false
	for _, sAny := range servers {
		s := sAny.(map[string]any)
		if _, ok := s["address"]; ok {
			t.Errorf("server %v uses legacy address field", s["tag"])
		}
		if _, ok := s["address_resolver"]; ok {
			t.Errorf("server %v uses legacy address_resolver field", s["tag"])
		}
		if s["type"] == nil {
			t.Errorf("server %v is missing type field", s["tag"])
		}
		if s["tag"] == "dns_fakeip" {
			fakeipFound = true
			if s["type"] != "fakeip" {
				t.Errorf("expected dns_fakeip type 'fakeip', got %v", s["type"])
			}
			if s["inet4_range"] != "198.18.0.0/15" {
				t.Errorf("unexpected fakeip inet4_range: %v", s["inet4_range"])
			}
			if _, ok := s["inet6_range"]; ok {
				t.Errorf("fakeip inet6_range must be omitted when IPv6 is disabled")
			}
		}
	}
	if !fakeipFound {
		t.Errorf("fakeip DNS server not found")
	}

	// 空 direct outbound 不能作为 DNS detour，否则 sing-box 启动时报
	// "detour to an empty direct outbound makes no sense"
	emptyDirectTags := make(map[string]bool)
	for _, oAny := range root["outbounds"].([]any) {
		o := oAny.(map[string]any)
		if tag, ok := o["tag"].(string); ok && o["type"] == "direct" && len(o) == 2 {
			emptyDirectTags[tag] = true
		}
	}
	for _, sAny := range servers {
		s := sAny.(map[string]any)
		if detour, ok := s["detour"].(string); ok && emptyDirectTags[detour] {
			t.Errorf("DNS server %v detours to empty direct outbound %q", s["tag"], detour)
		}
	}

	hasPredefinedReject := false
	for _, rAny := range dns["rules"].([]any) {
		r := rAny.(map[string]any)
		if _, ok := r["outbound"]; ok {
			t.Errorf("deprecated dns rule 'outbound' item must not be used")
		}
		if r["action"] == "predefined" && r["rcode"] == "REFUSED" {
			hasPredefinedReject = true
		}
	}
	if !hasPredefinedReject {
		t.Errorf("expected predefined REFUSED DNS rule for blocked domains")
	}

	route := root["route"].(map[string]any)
	if route["default_domain_resolver"] != "dns_direct" {
		t.Errorf("expected route.default_domain_resolver 'dns_direct', got %v", route["default_domain_resolver"])
	}
}

func TestBuildSingBoxConfig_OptionsOverride(t *testing.T) {
	opts := model.ConvertOptions{
		Preset:     "standard",
		SSHMode:    "proxy",
		WebRTCMode: "direct",
	}

	configJSON, err := BuildSingBoxConfig(sampleNodes(), opts)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	json.Unmarshal(configJSON, &root)
	outbounds := root["outbounds"].([]any)
	groupMap := make(map[string]map[string]any)
	for _, oAny := range outbounds {
		o := oAny.(map[string]any)
		if tag, ok := o["tag"].(string); ok {
			groupMap[tag] = o
		}
	}

	if groupMap["SSH出口"]["default"] != "节点选择" {
		t.Errorf("expected SSH出口 default '节点选择', got %v", groupMap["SSH出口"]["default"])
	}
	if groupMap["WebRTC防护"]["default"] != "全局直连" {
		t.Errorf("expected WebRTC防护 default '全局直连', got %v", groupMap["WebRTC防护"]["default"])
	}
	if _, ok := groupMap["AI服务"]; ok {
		t.Errorf("standard preset should not include 'AI服务'")
	}
}

func TestBuildSingBoxConfig_AllowInsecure(t *testing.T) {
	// 1. 默认或 AllowInsecure=false
	optsFalse := model.ConvertOptions{AllowInsecure: false}
	cfgFalse, err := BuildSingBoxConfig(sampleNodes(), optsFalse)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}
	var rootFalse map[string]any
	json.Unmarshal(cfgFalse, &rootFalse)
	for _, oAny := range rootFalse["outbounds"].([]any) {
		o := oAny.(map[string]any)
		tls, _ := o["tls"].(map[string]any)
		if o["tag"] == "香港 01" {
			if tls["insecure"] != false {
				t.Errorf("expected 香港 01 insecure=false when AllowInsecure=false, got %v", tls["insecure"])
			}
		} else if o["tag"] == "日本 01" {
			if tls["insecure"] != true {
				t.Errorf("expected 日本 01 insecure=true (node-level), got %v", tls["insecure"])
			}
		}
	}

	// 2. AllowInsecure=true
	optsTrue := model.ConvertOptions{AllowInsecure: true}
	cfgTrue, err := BuildSingBoxConfig(sampleNodes(), optsTrue)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}
	var rootTrue map[string]any
	json.Unmarshal(cfgTrue, &rootTrue)
	for _, oAny := range rootTrue["outbounds"].([]any) {
		o := oAny.(map[string]any)
		if o["type"] == "trojan" {
			tls, _ := o["tls"].(map[string]any)
			if tls["insecure"] != true {
				t.Errorf("expected node %s insecure=true when AllowInsecure=true, got %v", o["tag"], tls["insecure"])
			}
		}
	}
}

func TestParseCustomRules_SkipsInvalidPortAndIP(t *testing.T) {
	rules, _ := ParseCustomRules("port:0=block,port:99999=direct,port:abc=proxy,ip:abc=direct,ip:1.2.3.4/32=direct,ip:1.2.3.4=proxy,port:443=block,port:2222=SSH出口")
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d (%#v)", len(rules), rules)
	}

	seen := map[string]bool{}
	for _, rule := range rules {
		if cidrs, ok := rule["ip_cidr"].([]string); ok && len(cidrs) == 1 {
			seen["ip:"+cidrs[0]] = true
		}
		if ports, ok := rule["port"].([]int); ok && len(ports) == 1 {
			outbound, _ := rule["outbound"].(string)
			seen["port:"+outbound] = true
			if ports[0] != 443 && ports[0] != 2222 {
				t.Errorf("unexpected port %d", ports[0])
			}
		}
	}
	for _, key := range []string{"ip:1.2.3.4/32", "ip:1.2.3.4", "port:全局拦截", "port:SSH出口"} {
		if !seen[key] {
			t.Errorf("missing %s in %#v", key, rules)
		}
	}
}

func TestBuildSingBoxConfig_IPv6Option(t *testing.T) {
	configJSON, err := BuildSingBoxConfig(sampleNodes(), model.ConvertOptions{Preset: "geek", EnableIPv6: true})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		t.Fatalf("failed to unmarshal generated json: %v", err)
	}

	tun := root["inbounds"].([]any)[0].(map[string]any)
	addresses, _ := tun["address"].([]any)
	if len(addresses) != 2 || addresses[1] != "fdfe:dcba:9876::1/126" {
		t.Errorf("expected dual-stack tun address when IPv6 enabled, got %v", tun["address"])
	}

	dns := root["dns"].(map[string]any)
	if dns["strategy"] != "prefer_ipv4" {
		t.Errorf("expected dns strategy prefer_ipv4 when IPv6 enabled, got %v", dns["strategy"])
	}

	for _, sAny := range dns["servers"].([]any) {
		s := sAny.(map[string]any)
		if s["tag"] == "dns_fakeip" && s["inet6_range"] != "fc00::/18" {
			t.Errorf("expected fakeip inet6_range fc00::/18 when IPv6 enabled, got %v", s["inet6_range"])
		}
	}
}

func TestParseCustomRules_GeositeGeoIP(t *testing.T) {
	raw := "geosite:Netflix=proxy,geoip:US=direct,geosite:geolocation-!cn=proxy,geosite:google@cn=direct,geosite:../x=proxy,geosite:foo/bar=direct,geoip:=proxy,geosite:has space=block"
	rules, _ := ParseCustomRules(raw)
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d (%#v)", len(rules), rules)
	}

	want := []struct {
		tag, outbound string
	}{
		{"geosite-netflix", "节点选择"},
		{"geoip-us", "全局直连"},
		{"geosite-geolocation-!cn", "节点选择"},
		{"geosite-google@cn", "全局直连"},
	}
	for i, w := range want {
		tags, _ := rules[i]["rule_set"].([]string)
		if len(tags) != 1 || tags[0] != w.tag || rules[i]["outbound"] != w.outbound {
			t.Errorf("rule %d: got %#v, want %s -> %s", i, rules[i], w.tag, w.outbound)
		}
	}
}

func TestCustomGeositeDNS_FirstRuleWins(t *testing.T) {
	rules, _ := ParseCustomRules("geosite:apple=direct,geosite:apple=proxy,geosite:netflix=block,geoip:us=direct")
	proxy, direct := customGeositeDNS(rules)
	if len(proxy) != 0 {
		t.Fatalf("expected no proxy geosite, got %#v", proxy)
	}
	if len(direct) != 1 || direct[0] != "geosite-apple" {
		t.Fatalf("expected direct geosite-apple, got %#v", direct)
	}
}

func TestBuildSingBoxConfig_CustomGeosite(t *testing.T) {
	opts := model.ConvertOptions{
		Preset:      "geek",
		CustomRules: "geosite:netflix=proxy,geosite:apple=direct,geoip:us=proxy,geosite:cn=direct,geosite:openai=proxy,geosite:ads=block",
	}
	configJSON, err := BuildSingBoxConfig(sampleNodes(), opts)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		t.Fatalf("failed to unmarshal generated json: %v", err)
	}

	route := root["route"].(map[string]any)
	counts := map[string]int{}
	urls := map[string]string{}
	var netflixSet map[string]any
	for _, item := range route["rule_set"].([]any) {
		set := item.(map[string]any)
		tag := set["tag"].(string)
		counts[tag]++
		urls[tag], _ = set["url"].(string)
		if tag == "geosite-netflix" {
			netflixSet = set
		}
	}
	for _, tag := range []string{"geosite-cn", "geosite-openai", "geosite-netflix", "geosite-apple", "geoip-us", "geosite-ads"} {
		if counts[tag] != 1 {
			t.Errorf("rule set %s count = %d, want 1", tag, counts[tag])
		}
	}
	if urls["geosite-cn"] != "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs" {
		t.Errorf("built-in geosite-cn url changed: %s", urls["geosite-cn"])
	}
	if urls["geosite-openai"] != "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs" {
		t.Errorf("built-in geosite-openai url changed: %s", urls["geosite-openai"])
	}
	if urls["geosite-netflix"] != "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs" {
		t.Errorf("geosite-netflix url: %s", urls["geosite-netflix"])
	}
	if urls["geosite-apple"] != "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-apple.srs" {
		t.Errorf("geosite-apple url: %s", urls["geosite-apple"])
	}
	if urls["geoip-us"] != "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-us.srs" {
		t.Errorf("geoip-us url: %s", urls["geoip-us"])
	}
	if netflixSet["type"] != "remote" || netflixSet["format"] != "binary" || netflixSet["download_detour"] != "节点选择" {
		t.Errorf("geosite-netflix rule set shape: %#v", netflixSet)
	}

	netflixIdx, cnIdx := -1, -1
	for idx, rAny := range route["rules"].([]any) {
		r := rAny.(map[string]any)
		tags := jsonStringList(r["rule_set"])
		if containsString(tags, "geosite-netflix") && r["outbound"] == "节点选择" && netflixIdx == -1 {
			netflixIdx = idx
		}
		if containsString(tags, "geosite-cn") && cnIdx == -1 {
			cnIdx = idx
		}
		if containsString(tags, "geosite-ads") && r["outbound"] != "全局拦截" {
			t.Errorf("geosite-ads outbound: %v", r["outbound"])
		}
		if containsString(tags, "geoip-us") && r["outbound"] != "节点选择" {
			t.Errorf("geoip-us outbound: %v", r["outbound"])
		}
	}
	if netflixIdx == -1 || cnIdx == -1 || netflixIdx >= cnIdx {
		t.Errorf("custom geosite-netflix (%d) should be before geosite-cn (%d)", netflixIdx, cnIdx)
	}

	dns := root["dns"].(map[string]any)
	proxyIdx, cnDNSIdx, directIdx, fakeipIdx := -1, -1, -1, -1
	for idx, rAny := range dns["rules"].([]any) {
		r := rAny.(map[string]any)
		tags := jsonStringList(r["rule_set"])
		if containsString(tags, "geoip-us") || containsString(tags, "geosite-ads") {
			t.Errorf("geoip and blocked geosite must stay out of DNS rules: %#v", r)
		}
		if r["server"] == "dns_fakeip" && containsString(tags, "geosite-netflix") {
			proxyIdx = idx
			if !containsString(tags, "geosite-openai") {
				t.Errorf("proxy DNS rule missing geosite-openai: %#v", r)
			}
			queryTypes := jsonStringList(r["query_type"])
			if !containsString(queryTypes, "A") || !containsString(queryTypes, "AAAA") {
				t.Errorf("proxy DNS rule query_type: %#v", r["query_type"])
			}
		}
		if r["server"] == "dns_direct" && containsString(tags, "geosite-cn") && cnDNSIdx == -1 {
			cnDNSIdx = idx
		}
		if r["server"] == "dns_direct" && containsString(tags, "geosite-apple") {
			directIdx = idx
		}
		if r["server"] == "dns_fakeip" && r["rule_set"] == nil {
			fakeipIdx = idx
		}
	}
	if proxyIdx == -1 || cnDNSIdx == -1 || proxyIdx >= cnDNSIdx {
		t.Errorf("proxy geosite DNS (%d) should be before geosite-cn (%d)", proxyIdx, cnDNSIdx)
	}
	if directIdx == -1 || fakeipIdx == -1 || directIdx >= fakeipIdx {
		t.Errorf("direct geosite DNS (%d) should be before fakeip (%d)", directIdx, fakeipIdx)
	}
}

func jsonStringList(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestBuildSingBoxConfig_TagDeduplicationAndReserved(t *testing.T) {
	nodes := []*model.Node{
		{
			Tag:      "香港 01",
			Type:     "trojan",
			Server:   "hk1.example.com",
			Port:     443,
			Password: "pwd1",
		},
		{
			Tag:      "香港 01",
			Type:     "trojan",
			Server:   "hk2.example.com",
			Port:     443,
			Password: "pwd2",
		},
		{
			Tag:      "自动选择",
			Type:     "trojan",
			Server:   "hk3.example.com",
			Port:     443,
			Password: "pwd3",
		},
		{
			Tag:      "",
			Type:     "trojan",
			Server:   "hk4.example.com",
			Port:     443,
			Password: "pwd4",
		},
	}

	cfgJSON, err := BuildSingBoxConfig(nodes, model.ConvertOptions{})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(cfgJSON, &root); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	outbounds, _ := root["outbounds"].([]any)
	nodeOutboundTags := make([]string, 0)
	for _, ob := range outbounds {
		obMap, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		if obMap["type"] == "trojan" {
			nodeOutboundTags = append(nodeOutboundTags, obMap["tag"].(string))
		}
	}

	wantTags := []string{"香港 01", "香港 01 (2)", "自动选择 (2)", "TROJAN-hk4.example.com:443"}
	if len(nodeOutboundTags) != len(wantTags) {
		t.Fatalf("expected %d node outbounds, got %d: %v", len(wantTags), len(nodeOutboundTags), nodeOutboundTags)
	}
	for i, want := range wantTags {
		if nodeOutboundTags[i] != want {
			t.Errorf("node outbound [%d] tag = %q; want %q", i, nodeOutboundTags[i], want)
		}
	}
}

func TestBuildSingBoxConfig_MultiProtocolOutbounds(t *testing.T) {
	nodes := []*model.Node{
		{
			Tag:            "VLESS Reality",
			Type:           "vless",
			Server:         "vless.example.com",
			Port:           443,
			UUID:           "uuid-1234",
			Flow:           "xtls-rprx-vision",
			RealityPubKey:  "pubkey-xyz",
			RealityShortID: "sid-xyz",
		},
		{
			Tag:          "HY2 Node",
			Type:         "hysteria2",
			Server:       "hy2.example.com",
			Port:         8443,
			Password:     "hy2pass",
			ObfsType:     "salamander",
			ObfsPassword: "obfspassword",
		},
		{
			Tag:      "SS Node",
			Type:     "shadowsocks",
			Server:   "ss.example.com",
			Port:     8388,
			Method:   "aes-128-gcm",
			Password: "sspassword",
		},
		{
			Tag:     "VMess Node",
			Type:    "vmess",
			Server:  "vmess.example.com",
			Port:    443,
			UUID:    "uuid-vmess",
			AlterID: 0,
		},
	}

	cfgJSON, err := BuildSingBoxConfig(nodes, model.ConvertOptions{})
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(cfgJSON, &root); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	outbounds, _ := root["outbounds"].([]any)
	byTag := make(map[string]map[string]any)
	for _, ob := range outbounds {
		obMap, ok := ob.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := obMap["tag"].(string)
		byTag[tag] = obMap
	}

	// 1. Check VLESS
	vlessOB := byTag["VLESS Reality"]
	if vlessOB == nil || vlessOB["type"] != "vless" {
		t.Fatalf("missing or wrong vless outbound: %v", vlessOB)
	}
	if vlessOB["flow"] != "xtls-rprx-vision" || vlessOB["uuid"] != "uuid-1234" {
		t.Errorf("vless fields mismatch: %v", vlessOB)
	}
	tlsMap, _ := vlessOB["tls"].(map[string]any)
	realityMap, _ := tlsMap["reality"].(map[string]any)
	if realityMap == nil || realityMap["public_key"] != "pubkey-xyz" || realityMap["short_id"] != "sid-xyz" {
		t.Errorf("vless reality mismatch: %v", realityMap)
	}
	utlsMap, _ := tlsMap["utls"].(map[string]any)
	if utlsMap == nil || utlsMap["enabled"] != true || utlsMap["fingerprint"] != "chrome" {
		t.Errorf("vless utls mismatch: %v", utlsMap)
	}

	// 2. Check Hysteria2
	hy2OB := byTag["HY2 Node"]
	if hy2OB == nil || hy2OB["type"] != "hysteria2" {
		t.Fatalf("missing or wrong hy2 outbound: %v", hy2OB)
	}
	hy2TLS, _ := hy2OB["tls"].(map[string]any)
	alpnList := jsonStringList(hy2TLS["alpn"])
	if len(alpnList) != 1 || alpnList[0] != "h3" {
		t.Errorf("hy2 ALPN should be [h3], got %v", alpnList)
	}
	obfsMap, _ := hy2OB["obfs"].(map[string]any)
	if obfsMap == nil || obfsMap["type"] != "salamander" || obfsMap["password"] != "obfspassword" {
		t.Errorf("hy2 obfs mismatch: %v", obfsMap)
	}

	// 3. Check Shadowsocks
	ssOB := byTag["SS Node"]
	if ssOB == nil || ssOB["type"] != "shadowsocks" {
		t.Fatalf("missing or wrong ss outbound: %v", ssOB)
	}
	if ssOB["method"] != "aes-128-gcm" || ssOB["password"] != "sspassword" {
		t.Errorf("ss fields mismatch: %v", ssOB)
	}

	// 4. Check VMess
	vmessOB := byTag["VMess Node"]
	if vmessOB == nil || vmessOB["type"] != "vmess" {
		t.Fatalf("missing or wrong vmess outbound: %v", vmessOB)
	}
	if vmessOB["security"] != "auto" || vmessOB["uuid"] != "uuid-vmess" {
		t.Errorf("vmess fields mismatch: %v", vmessOB)
	}
}

func TestBuildOutbounds_NilNodesAndReservedTags(t *testing.T) {
	nodes := []*model.Node{
		nil,
		{
			Tag:      "AI服务",
			Type:     "trojan",
			Server:   "1.2.3.4",
			Port:     443,
			Password: "pwd",
		},
		nil,
		{
			Tag:      "开发服务",
			Type:     "trojan",
			Server:   "5.6.7.8",
			Port:     443,
			Password: "pwd",
		},
	}

	outbounds := BuildOutbounds(nodes, model.ConvertOptions{})
	if len(outbounds) == 0 {
		t.Fatalf("expected non-empty outbounds")
	}

	var nodeTags []string
	for _, ob := range outbounds {
		if ob["type"] == "trojan" {
			nodeTags = append(nodeTags, ob["tag"].(string))
		}
	}

	if len(nodeTags) != 2 {
		t.Fatalf("expected 2 valid trojan nodes, got %d", len(nodeTags))
	}
	if nodeTags[0] != "AI服务 (2)" {
		t.Errorf("expected tag 'AI服务 (2)', got %q", nodeTags[0])
	}
	if nodeTags[1] != "开发服务 (2)" {
		t.Errorf("expected tag '开发服务 (2)', got %q", nodeTags[1])
	}
}

func TestBuildSingBoxConfig_RuleCDN(t *testing.T) {
	tests := []struct {
		name       string
		ruleCDN    bool
		urlPrefix  string
		branchPart string
	}{
		{
			name:       "default github raw",
			ruleCDN:    false,
			urlPrefix:  "https://raw.githubusercontent.com/SagerNet/",
			branchPart: "/rule-set/",
		},
		{
			name:       "jsdelivr cdn",
			ruleCDN:    true,
			urlPrefix:  "https://cdn.jsdelivr.net/gh/SagerNet/",
			branchPart: "@rule-set/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := model.ConvertOptions{
				Preset:      "geek",
				RuleCDN:     tc.ruleCDN,
				CustomRules: "geosite:netflix=proxy,geoip:us=direct",
			}
			configJSON, err := BuildSingBoxConfig(sampleNodes(), opts)
			if err != nil {
				t.Fatalf("BuildSingBoxConfig failed: %v", err)
			}
			var root map[string]any
			if err := json.Unmarshal(configJSON, &root); err != nil {
				t.Fatalf("failed to unmarshal generated json: %v", err)
			}
			route, ok := root["route"].(map[string]any)
			if !ok {
				t.Fatalf("route section missing")
			}
			ruleSets, ok := route["rule_set"].([]any)
			if !ok || len(ruleSets) == 0 {
				t.Fatalf("rule_set missing or empty")
			}
			for _, rsAny := range ruleSets {
				rs, ok := rsAny.(map[string]any)
				if !ok {
					continue
				}
				url, _ := rs["url"].(string)
				tag, _ := rs["tag"].(string)
				if !strings.HasPrefix(url, tc.urlPrefix) {
					t.Errorf("[%s] rule_set %q url %q does not have prefix %q", tc.name, tag, url, tc.urlPrefix)
				}
				if !strings.Contains(url, tc.branchPart) {
					t.Errorf("[%s] rule_set %q url %q does not contain %q", tc.name, tag, url, tc.branchPart)
				}
			}
		})
	}
}

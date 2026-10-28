package builder

import (
	"net"
	"strconv"
	"strings"

	"sub2sfm/pkg/model"
)

// ParseCustomRules 解析用户自定义的分流规则
// 格式支持逗号、分号或换行分隔：
// domain:myvps.com=direct,suffix:google.com=proxy,ip:1.1.1.1/32=direct,port:2222=SSH出口,geosite:netflix=proxy,geoip:us=direct
func ParseCustomRules(raw string) ([]map[string]any, []string) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	separators := []string{",", ";", "\n"}
	tokens := []string{raw}
	for _, sep := range separators {
		var next []string
		for _, t := range tokens {
			next = append(next, strings.Split(t, sep)...)
		}
		tokens = next
	}

	var rules []map[string]any
	var directDomains []string

	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" || strings.HasPrefix(token, "#") {
			continue
		}

		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}

		criteria := strings.TrimSpace(parts[0])
		target := strings.TrimSpace(parts[1])

		// 目标出站映射
		action := "route"
		outbound := target
		switch strings.ToLower(target) {
		case "direct":
			outbound = "全局直连"
		case "proxy":
			outbound = "节点选择"
		case "block", "全局拦截":
			outbound = "全局拦截"
		}

		kv := strings.SplitN(criteria, ":", 2)
		if len(kv) != 2 {
			continue
		}

		ruleType := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])

		rule := map[string]any{"action": action}
		if action == "route" {
			rule["outbound"] = outbound
		}

		switch ruleType {
		case "domain":
			rule["domain"] = []string{val}
			if outbound == "全局直连" {
				directDomains = append(directDomains, val)
			}
		case "suffix":
			rule["domain_suffix"] = []string{val}
			if outbound == "全局直连" {
				directDomains = append(directDomains, val)
			}
		case "keyword":
			rule["domain_keyword"] = []string{val}
		case "ip":
			if !validIPCIDR(val) {
				continue
			}
			rule["ip_cidr"] = []string{val}
		case "port":
			p, err := strconv.Atoi(val)
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			rule["port"] = []int{p}
		case "geosite", "geoip":
			name := strings.ToLower(val)
			if !validRuleSetName(name) {
				continue
			}
			rule["rule_set"] = []string{ruleType + "-" + name}
		default:
			continue
		}

		rules = append(rules, rule)
	}

	return rules, directDomains
}

func validIPCIDR(val string) bool {
	if strings.Contains(val, "/") {
		_, _, err := net.ParseCIDR(val)
		return err == nil
	}
	return net.ParseIP(val) != nil
}

// validRuleSetName 限制规则集名字，避免用户输入改写远程规则集 URL。
func validRuleSetName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '@' || r == '!' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// customGeositeDNS 按每个 geosite tag 的第一条自定义规则决定 DNS。
// 代理要排在内置 geosite-cn 之前，否则国内列表里的域名仍走直连 DNS。
func customGeositeDNS(rules []map[string]any) (proxy, direct []string) {
	seen := map[string]bool{}
	for _, rule := range rules {
		tags, ok := rule["rule_set"].([]string)
		if !ok {
			continue
		}
		outbound, _ := rule["outbound"].(string)
		for _, tag := range tags {
			if !strings.HasPrefix(tag, "geosite-") || seen[tag] {
				continue
			}
			seen[tag] = true
			switch outbound {
			case "节点选择":
				proxy = append(proxy, tag)
			case "全局直连":
				direct = append(direct, tag)
			}
		}
	}
	return proxy, direct
}

func formatRuleSetURL(baseRepo, fileName string, useCDN bool) string {
	if useCDN {
		return "https://cdn.jsdelivr.net/gh/SagerNet/" + baseRepo + "@rule-set/" + fileName
	}
	return "https://raw.githubusercontent.com/SagerNet/" + baseRepo + "/rule-set/" + fileName
}

func appendCustomRuleSets(sets []map[string]any, rules []map[string]any, useCDN bool) []map[string]any {
	seen := map[string]bool{}
	for _, set := range sets {
		if tag, ok := set["tag"].(string); ok {
			seen[tag] = true
		}
	}
	for _, rule := range rules {
		tags, ok := rule["rule_set"].([]string)
		if !ok {
			continue
		}
		for _, tag := range tags {
			if seen[tag] {
				continue
			}
			url, ok := ruleSetURL(tag, useCDN)
			if !ok {
				continue
			}
			seen[tag] = true
			sets = append(sets, map[string]any{
				"tag":             tag,
				"type":            "remote",
				"format":          "binary",
				"url":             url,
				"download_detour": "节点选择",
			})
		}
	}
	return sets
}

func ruleSetURL(tag string, useCDN bool) (string, bool) {
	const (
		geositePrefix = "geosite-"
		geoipPrefix   = "geoip-"
	)
	switch {
	case strings.HasPrefix(tag, geositePrefix):
		name := strings.TrimPrefix(tag, geositePrefix)
		if !validRuleSetName(name) {
			return "", false
		}
		return formatRuleSetURL("sing-geosite", "geosite-"+name+".srs", useCDN), true
	case strings.HasPrefix(tag, geoipPrefix):
		name := strings.TrimPrefix(tag, geoipPrefix)
		if !validRuleSetName(name) {
			return "", false
		}
		return formatRuleSetURL("sing-geoip", "geoip-"+name+".srs", useCDN), true
	default:
		return "", false
	}
}

// BuildRoute 构建路由表与规则集
func BuildRoute(opts model.ConvertOptions, customRules []map[string]any) map[string]any {
	var rules []map[string]any

	// 1. 协议嗅探（替代已移除的 inbound.sniff）
	rules = append(rules, map[string]any{
		"inbound": []string{"tun-in"},
		"action":  "sniff",
	})

	// 2. DNS 劫持
	rules = append(rules,
		map[string]any{
			"protocol": "dns",
			"action":   "hijack-dns",
		},
		map[string]any{
			"port":   []int{53},
			"action": "hijack-dns",
		},
	)

	// 3. 私有与局域网 IP 直连
	rules = append(rules, map[string]any{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "全局直连",
	})

	// 4. WebRTC / STUN 拦截（防止探测真实国内公网 IP）
	webrtcRules := []map[string]any{
		{
			"protocol": "stun",
		},
		{
			"port": []int{3478, 5349, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309},
		},
		{
			"domain_keyword": []string{"stun", "turn"},
		},
	}
	for _, rule := range webrtcRules {
		rule["action"] = "route"
		rule["outbound"] = "WebRTC防护"
		rules = append(rules, rule)
	}

	// 5. SSH 独立策略组（解决 macOS 频繁断开问题）
	rules = append(rules, map[string]any{
		"port":     []int{22},
		"action":   "route",
		"outbound": "SSH出口",
	})

	// 6. 注入用户自定义规则（优先级高于地理分流）
	if len(customRules) > 0 {
		rules = append(rules, customRules...)
	}

	// 7. 基础广告拦截
	rules = append(rules, map[string]any{
		"rule_set": []string{"geosite-category-ads-all"},
		"action":   "route",
		"outbound": "全局拦截",
	})

	preset := strings.ToLower(opts.Preset)
	if preset == "" || preset == "geek" {
		// 默认分流
		rules = append(rules,
			map[string]any{
				"rule_set": []string{"geosite-openai"},
				"action":   "route",
				"outbound": "AI服务",
			},
			map[string]any{
				"rule_set": []string{"geosite-github", "geosite-gitlab"},
				"action":   "route",
				"outbound": "开发服务",
			},
			map[string]any{
				"rule_set": []string{"geosite-private"},
				"action":   "route",
				"outbound": "全局直连",
			},
			map[string]any{
				"rule_set": []string{"geosite-cn"},
				"action":   "route",
				"outbound": "全局直连",
			},
			map[string]any{
				"rule_set": []string{"geoip-cn"},
				"action":   "route",
				"outbound": "全局直连",
			},
		)
	} else if preset == "standard" {
		// 标准分流模式
		rules = append(rules,
			map[string]any{
				"rule_set": []string{"geosite-private"},
				"action":   "route",
				"outbound": "全局直连",
			},
			map[string]any{
				"rule_set": []string{"geosite-cn"},
				"action":   "route",
				"outbound": "全局直连",
			},
			map[string]any{
				"rule_set": []string{"geoip-cn"},
				"action":   "route",
				"outbound": "全局直连",
			},
		)
	}

	// 规则集定义
	ruleSets := []map[string]any{
		{
			"tag":             "geoip-cn",
			"type":            "remote",
			"format":          "binary",
			"url":             formatRuleSetURL("sing-geoip", "geoip-cn.srs", opts.RuleCDN),
			"download_detour": "节点选择",
		},
		{
			"tag":             "geosite-cn",
			"type":            "remote",
			"format":          "binary",
			"url":             formatRuleSetURL("sing-geosite", "geosite-geolocation-cn.srs", opts.RuleCDN),
			"download_detour": "节点选择",
		},
		{
			"tag":             "geosite-category-ads-all",
			"type":            "remote",
			"format":          "binary",
			"url":             formatRuleSetURL("sing-geosite", "geosite-category-ads-all.srs", opts.RuleCDN),
			"download_detour": "节点选择",
		},
		{
			"tag":             "geosite-private",
			"type":            "remote",
			"format":          "binary",
			"url":             formatRuleSetURL("sing-geosite", "geosite-private.srs", opts.RuleCDN),
			"download_detour": "节点选择",
		},
	}

	if preset == "" || preset == "geek" {
		ruleSets = append(ruleSets,
			map[string]any{
				"tag":             "geosite-openai",
				"type":            "remote",
				"format":          "binary",
				"url":             formatRuleSetURL("sing-geosite", "geosite-openai.srs", opts.RuleCDN),
				"download_detour": "节点选择",
			},
			map[string]any{
				"tag":             "geosite-github",
				"type":            "remote",
				"format":          "binary",
				"url":             formatRuleSetURL("sing-geosite", "geosite-github.srs", opts.RuleCDN),
				"download_detour": "节点选择",
			},
			map[string]any{
				"tag":             "geosite-gitlab",
				"type":            "remote",
				"format":          "binary",
				"url":             formatRuleSetURL("sing-geosite", "geosite-gitlab.srs", opts.RuleCDN),
				"download_detour": "节点选择",
			},
		)
	}

	ruleSets = appendCustomRuleSets(ruleSets, customRules, opts.RuleCDN)

	return map[string]any{
		"rules":                   rules,
		"rule_set":                ruleSets,
		"final":                   "节点选择",
		"auto_detect_interface":   true,
		"default_domain_resolver": "dns_direct",
	}
}

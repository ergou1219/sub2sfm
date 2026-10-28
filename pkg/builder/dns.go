package builder

import (
	"sub2sfm/pkg/model"
)

// BuildDNS 构建分流防泄漏 DNS 配置（Sing-box 1.12+ 新 DNS Server 格式）
func BuildDNS(opts model.ConvertOptions, directDomains, proxyGeosites, directGeosites []string) map[string]any {
	servers := []map[string]any{
		{
			// 不设置 detour：新格式默认使用空 direct 拨号，指向空的
			// "全局直连" outbound 会导致 sing-box 启动报错
			// (detour to an empty direct outbound makes no sense)
			"type":   "https",
			"tag":    "dns_direct",
			"server": "223.5.5.5",
		},
		{
			"type":   "https",
			"tag":    "dns_proxy",
			"server": "8.8.8.8",
			"detour": "节点选择",
		},
	}

	fakeip := map[string]any{
		"type":        "fakeip",
		"tag":         "dns_fakeip",
		"inet4_range": "198.18.0.0/15",
	}
	if opts.EnableIPv6 {
		fakeip["inet6_range"] = "fc00::/18"
	}
	servers = append(servers, fakeip)

	rules := []map[string]any{
		{
			// 拦截广告域名
			"rule_set": []string{"geosite-category-ads-all"},
			"action":   "predefined",
			"rcode":    "REFUSED",
		},
		{
			// 拦截 Type 65 (HTTPS) 查询，阻止苹果/Chrome ECH 绕过代理
			"query_type": []string{"HTTPS"},
			"action":     "predefined",
			"rcode":      "REFUSED",
		},
		{
			// 私有域名解析直连
			"rule_set": []string{"geosite-private"},
			"action":   "route",
			"server":   "dns_direct",
		},
	}

	// 自定义代理域名要先于 geosite-cn，否则国内列表里的名字仍被直连 DNS 解析。
	if len(proxyGeosites) > 0 {
		rules = append(rules, map[string]any{
			"rule_set":   proxyGeosites,
			"query_type": []string{"A", "AAAA"},
			"action":     "route",
			"server":     "dns_fakeip",
		})
	}

	rules = append(rules, map[string]any{
		// 国内域名解析直连（优先于 fakeip，避免国内 CDN 解析错乱）
		"rule_set": []string{"geosite-cn"},
		"action":   "route",
		"server":   "dns_direct",
	})

	if len(directGeosites) > 0 {
		rules = append(rules, map[string]any{
			"rule_set": directGeosites,
			"action":   "route",
			"server":   "dns_direct",
		})
	}

	// 自定义直连域名插入在 fakeip 前
	if len(directDomains) > 0 {
		rules = append(rules, map[string]any{
			"domain": directDomains,
			"action": "route",
			"server": "dns_direct",
		})
	}

	// 其余境外域名 A/AAAA 查询走 Fake-IP，由远程代理节点进行无污染远端解析
	rules = append(rules, map[string]any{
		"query_type": []string{"A", "AAAA"},
		"action":     "route",
		"server":     "dns_fakeip",
	})

	// 关闭 IPv6 时只下发 A 记录：无全局 IPv6 的网络上，真实 AAAA 会让
	// Chrome/App 连进 TUN，直连拨号失败后 RST 且客户端不会回退 IPv4
	//（国内站点表现为 ERR_CONNECTION_RESET，代理站点正常）。
	strategy := "ipv4_only"
	if opts.EnableIPv6 {
		strategy = "prefer_ipv4"
	}

	return map[string]any{
		"servers":  servers,
		"rules":    rules,
		"final":    "dns_direct",
		"strategy": strategy,
	}
}

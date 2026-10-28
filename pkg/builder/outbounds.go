package builder

import (
	"fmt"
	"strings"

	"sub2sfm/pkg/model"
)

var reservedOutboundTags = map[string]bool{
	"节点选择":     true,
	"自动选择":     true,
	"全局直连":     true,
	"全局拦截":     true,
	"SSH出口":    true,
	"WebRTC防护": true,
	"漏网之鱼":     true,
	"AI服务":     true,
	"开发服务":     true,
	"direct":   true,
	"block":    true,
	"dns-out":  true,
}

func sanitizeAndDeduplicateNodes(nodes []*model.Node) []*model.Node {
	sanitized := make([]*model.Node, 0, len(nodes))
	usedTags := make(map[string]int)

	for _, n := range nodes {
		if n == nil {
			continue
		}
		nodeCopy := *n
		baseTag := strings.TrimSpace(nodeCopy.Tag)
		if baseTag == "" {
			baseTag = fmt.Sprintf("%s-%s:%d", strings.ToUpper(nodeCopy.Type), nodeCopy.Server, nodeCopy.Port)
		}

		finalTag := baseTag
		if reservedOutboundTags[finalTag] || usedTags[finalTag] > 0 {
			count := 2
			for {
				candidate := fmt.Sprintf("%s (%d)", baseTag, count)
				if !reservedOutboundTags[candidate] && usedTags[candidate] == 0 {
					finalTag = candidate
					break
				}
				count++
			}
		}

		usedTags[finalTag]++
		nodeCopy.Tag = finalTag
		sanitized = append(sanitized, &nodeCopy)
	}

	return sanitized
}

// BuildOutbounds 根据节点和转换选项构建完整的 Outbound 列表
func BuildOutbounds(nodes []*model.Node, opts model.ConvertOptions) []map[string]any {
	nodes = sanitizeAndDeduplicateNodes(nodes)
	var outbounds []map[string]any

	validNodes := make([]*model.Node, 0, len(nodes))
	nodeTags := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if isSupportedNodeType(n.Type) {
			validNodes = append(validNodes, n)
			nodeTags = append(nodeTags, n.Tag)
		}
	}
	// 1. 节点选择 (主选择器)
	selectorOutbounds := append([]string{"自动选择", "全局直连"}, nodeTags...)
	outbounds = append(outbounds, map[string]any{
		"type":      "selector",
		"tag":       "节点选择",
		"outbounds": selectorOutbounds,
		"default":   "自动选择",
	})

	// 2. 自动选择 (URLTest 自动优选)
	outbounds = append(outbounds, map[string]any{
		"type":      "urltest",
		"tag":       "自动选择",
		"outbounds": nodeTags,
		"url":       "https://www.gstatic.com/generate_204",
		"interval":  "3m",
		"tolerance": 50,
	})

	// 3. SSH 出口策略组 (彻底解决 SSH 断连问题)
	sshDefault := "全局直连"
	if strings.EqualFold(opts.SSHMode, "proxy") {
		sshDefault = "节点选择"
	}
	outbounds = append(outbounds, map[string]any{
		"type":      "selector",
		"tag":       "SSH出口",
		"outbounds": []string{"全局直连", "节点选择", "自动选择"},
		"default":   sshDefault,
	})

	// 4. WebRTC 防护策略组 (杜绝真实公网 IP 泄漏)
	webrtcDefault := "全局拦截"
	if strings.EqualFold(opts.WebRTCMode, "direct") {
		webrtcDefault = "全局直连"
	} else if strings.EqualFold(opts.WebRTCMode, "proxy") {
		webrtcDefault = "节点选择"
	}
	outbounds = append(outbounds, map[string]any{
		"type":      "selector",
		"tag":       "WebRTC防护",
		"outbounds": []string{"全局拦截", "全局直连", "节点选择"},
		"default":   webrtcDefault,
	})

	// 5. 默认分流的专项服务分流组
	if opts.Preset == "" || strings.EqualFold(opts.Preset, "geek") {
		aiOutbounds := append([]string{"节点选择", "自动选择", "全局直连"}, nodeTags...)
		outbounds = append(outbounds, map[string]any{
			"type":      "selector",
			"tag":       "AI服务",
			"outbounds": aiOutbounds,
			"default":   "节点选择",
		})

		devOutbounds := append([]string{"节点选择", "自动选择", "全局直连"}, nodeTags...)
		outbounds = append(outbounds, map[string]any{
			"type":      "selector",
			"tag":       "开发服务",
			"outbounds": devOutbounds,
			"default":   "节点选择",
		})
	}

	// 6. 基础系统出口
	outbounds = append(outbounds, map[string]any{
		"type": "direct",
		"tag":  "全局直连",
	})
	outbounds = append(outbounds, map[string]any{
		"type": "block",
		"tag":  "全局拦截",
	})

	// 7. 实体代理节点
	for _, n := range validNodes {
		if nodeMap := convertNode(n, opts.AllowInsecure); nodeMap != nil {
			outbounds = append(outbounds, nodeMap)
		}
	}

	return outbounds
}

func isSupportedNodeType(t string) bool {
	switch strings.ToLower(t) {
	case "trojan", "vless", "hysteria2", "hy2", "shadowsocks", "ss", "vmess":
		return true
	}
	return false
}

func buildTransport(n *model.Node) map[string]any {
	if strings.EqualFold(n.Network, "ws") {
		wsConfig := map[string]any{
			"type": "ws",
			"path": n.WSPath,
		}
		if len(n.WSHeaders) > 0 {
			wsConfig["headers"] = n.WSHeaders
		}
		return wsConfig
	} else if strings.EqualFold(n.Network, "grpc") {
		return map[string]any{
			"type":         "grpc",
			"service_name": n.GRPCService,
		}
	}
	return nil
}

func convertNode(n *model.Node, allowInsecure bool) map[string]any {
	sni := n.SNI
	if sni == "" {
		sni = n.Server
	}

	nodeType := strings.ToLower(n.Type)
	switch nodeType {
	case "trojan":
		tlsConfig := map[string]any{
			"enabled":     true,
			"server_name": sni,
			"insecure":    n.SkipCertVerify || allowInsecure,
		}
		if len(n.ALPN) > 0 {
			tlsConfig["alpn"] = n.ALPN
		}
		nodeMap := map[string]any{
			"type":        "trojan",
			"tag":         n.Tag,
			"server":      n.Server,
			"server_port": n.Port,
			"password":    n.Password,
			"tls":         tlsConfig,
		}
		if t := buildTransport(n); t != nil {
			nodeMap["transport"] = t
		}
		return nodeMap

	case "vless":
		nodeMap := map[string]any{
			"type":        "vless",
			"tag":         n.Tag,
			"server":      n.Server,
			"server_port": n.Port,
			"uuid":        n.UUID,
		}
		if n.Flow != "" {
			nodeMap["flow"] = n.Flow
		}
		if n.RealityPubKey != "" || n.SNI != "" || n.Port == 443 {
			tlsConfig := map[string]any{
				"enabled":     true,
				"server_name": sni,
				"insecure":    n.SkipCertVerify || allowInsecure,
			}
			if n.RealityPubKey != "" {
				tlsConfig["reality"] = map[string]any{
					"enabled":    true,
					"public_key": n.RealityPubKey,
					"short_id":   n.RealityShortID,
				}
				tlsConfig["utls"] = map[string]any{
					"enabled":     true,
					"fingerprint": "chrome",
				}
			}
			if len(n.ALPN) > 0 {
				tlsConfig["alpn"] = n.ALPN
			}
			nodeMap["tls"] = tlsConfig
		}
		if t := buildTransport(n); t != nil {
			nodeMap["transport"] = t
		}
		return nodeMap

	case "hysteria2", "hy2":
		alpn := n.ALPN
		if len(alpn) == 0 {
			alpn = []string{"h3"}
		}
		nodeMap := map[string]any{
			"type":        "hysteria2",
			"tag":         n.Tag,
			"server":      n.Server,
			"server_port": n.Port,
			"password":    n.Password,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": sni,
				"insecure":    n.SkipCertVerify || allowInsecure,
				"alpn":        alpn,
			},
		}
		if n.ObfsType != "" {
			nodeMap["obfs"] = map[string]any{
				"type":     n.ObfsType,
				"password": n.ObfsPassword,
			}
		}
		return nodeMap

	case "shadowsocks", "ss":
		return map[string]any{
			"type":        "shadowsocks",
			"tag":         n.Tag,
			"server":      n.Server,
			"server_port": n.Port,
			"method":      n.Method,
			"password":    n.Password,
		}

	case "vmess":
		nodeMap := map[string]any{
			"type":        "vmess",
			"tag":         n.Tag,
			"server":      n.Server,
			"server_port": n.Port,
			"uuid":        n.UUID,
			"security":    "auto",
			"alter_id":    n.AlterID,
		}
		if n.SNI != "" || n.Port == 443 {
			tlsConfig := map[string]any{
				"enabled":     true,
				"server_name": sni,
				"insecure":    n.SkipCertVerify || allowInsecure,
			}
			if len(n.ALPN) > 0 {
				tlsConfig["alpn"] = n.ALPN
			}
			nodeMap["tls"] = tlsConfig
		}
		if t := buildTransport(n); t != nil {
			nodeMap["transport"] = t
		}
		return nodeMap

	default:
		return nil
	}
}

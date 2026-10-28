package builder

import "sub2sfm/pkg/model"

// BuildInbounds 构建入站配置，包含 macOS 专用的抗断连 TUN 和本地 Mixed 端口
func BuildInbounds(opts model.ConvertOptions) []map[string]any {
	addresses := []string{"172.19.0.1/30"}
	if opts.EnableIPv6 {
		addresses = append(addresses, "fdfe:dcba:9876::1/126")
	}

	tunInbound := map[string]any{
		"type":           "tun",
		"tag":            "tun-in",
		"interface_name": "utun",
		"address":        addresses,
		"mtu":            1500,    // 修复 9000 巨帧导致的 PMTU 黑洞与分片丢失
		"stack":          "mixed", // 强制 mixed 栈（TCP gVisor，UDP 系统直通），免疫 macOS socket 重置
		"auto_route":     true,
		"strict_route":   true,
	}

	mixedInbound := map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": 2080,
	}

	return []map[string]any{tunInbound, mixedInbound}
}

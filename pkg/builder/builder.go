package builder

import (
	"encoding/json"
	"fmt"

	"sub2sfm/pkg/model"
)

// BuildSingBoxConfig 整合各子模块，生成标准完整的 Sing-box 配置
func BuildSingBoxConfig(nodes []*model.Node, opts model.ConvertOptions) ([]byte, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("cannot build config: 0 nodes provided")
	}

	customRules, directDomains := ParseCustomRules(opts.CustomRules)
	proxyGeosites, directGeosites := customGeositeDNS(customRules)

	inbounds := BuildInbounds(opts)
	dnsConfig := BuildDNS(opts, directDomains, proxyGeosites, directGeosites)
	outbounds := BuildOutbounds(nodes, opts)
	routeConfig := BuildRoute(opts, customRules)

	config := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns":       dnsConfig,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     routeConfig,
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled":      true,
				"store_fakeip": true,
			},
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:9090",
				"secret":              "",
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sing-box config: %w", err)
	}

	return data, nil
}

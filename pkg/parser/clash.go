package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
	"sub2sfm/pkg/model"
)

type clashConfig struct {
	Proxies []clashProxy `yaml:"proxies"`
}

type clashRealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

type clashProxy struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"`
	Server         string            `yaml:"server"`
	Port           int               `yaml:"port"`
	Password       string            `yaml:"password"`
	SNI            string            `yaml:"sni"`
	ServerName     string            `yaml:"servername"`
	SkipCertVerify bool              `yaml:"skip-cert-verify"`
	UDP            *bool             `yaml:"udp"`
	ALPN           []string          `yaml:"alpn"`
	Network        string            `yaml:"network"`
	WSOpts         clashWSOpts       `yaml:"ws-opts"`
	WSPath         string            `yaml:"ws-path"`
	WSHeaders      map[string]string `yaml:"ws-headers"`
	GRPCOpts       clashGRPCOpts     `yaml:"grpc-opts"`
	UUID           string            `yaml:"uuid"`
	Cipher         string            `yaml:"cipher"`
	Flow           string            `yaml:"flow"`
	TLS            *bool             `yaml:"tls"`
	RealityOpts    clashRealityOpts  `yaml:"reality-opts"`
	Up             any               `yaml:"up"`
	Down           any               `yaml:"down"`
	Obfs           string            `yaml:"obfs"`
	ObfsPassword   string            `yaml:"obfs-password"`
	AlterID        int               `yaml:"alterId"`
}

type clashWSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type clashGRPCOpts struct {
	ServiceName string `yaml:"grpc-service-name"`
}

// ParseClashYAML 解析 Clash / Clash.Meta YAML 配置中的节点
func ParseClashYAML(content []byte) ([]*model.Node, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal clash yaml: %w", err)
	}

	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("no proxies in clash config")
	}

	var nodes []*model.Node
	for _, p := range cfg.Proxies {
		nodeType := strings.ToLower(strings.TrimSpace(p.Type))
		switch nodeType {
		case "trojan":
			nodeType = "trojan"
		case "vless":
			nodeType = "vless"
		case "hysteria2", "hy2":
			nodeType = "hysteria2"
		case "ss", "shadowsocks":
			nodeType = "shadowsocks"
		case "vmess":
			nodeType = "vmess"
		default:
			continue
		}

		sni := p.SNI
		if sni == "" {
			sni = p.ServerName
		}
		if sni == "" && (nodeType == "trojan" || nodeType == "hysteria2" || ((nodeType == "vless" || nodeType == "vmess") && (p.TLS != nil && *p.TLS || p.RealityOpts.PublicKey != ""))) {
			sni = p.Server
		}

		udp := true
		if p.UDP != nil {
			udp = *p.UDP
		}

		wsPath := p.WSPath
		if wsPath == "" {
			wsPath = p.WSOpts.Path
		}
		wsHeaders := p.WSHeaders
		if wsHeaders == nil {
			wsHeaders = p.WSOpts.Headers
		}

		grpcService := p.GRPCOpts.ServiceName

		upStr := ""
		if p.Up != nil {
			upStr = fmt.Sprint(p.Up)
		}
		downStr := ""
		if p.Down != nil {
			downStr = fmt.Sprint(p.Down)
		}

		node := &model.Node{
			Tag:            p.Name,
			Type:           nodeType,
			Server:         p.Server,
			Port:           p.Port,
			Password:       p.Password,
			SNI:            sni,
			SkipCertVerify: p.SkipCertVerify,
			ALPN:           p.ALPN,
			Network:        p.Network,
			WSPath:         wsPath,
			WSHeaders:      wsHeaders,
			GRPCService:    grpcService,
			UDP:            udp,
			UUID:           p.UUID,
			Flow:           p.Flow,
			Method:         p.Cipher,
			AlterID:        p.AlterID,
			Up:             upStr,
			Down:           downStr,
			ObfsType:       p.Obfs,
			ObfsPassword:   p.ObfsPassword,
			RealityPubKey:  p.RealityOpts.PublicKey,
			RealityShortID: p.RealityOpts.ShortID,
		}
		nodes = append(nodes, node)
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no supported proxies found in clash config")
	}

	return nodes, nil
}

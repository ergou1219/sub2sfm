package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"sub2sfm/pkg/model"
)

type singBoxConfig struct {
	Outbounds []singBoxOutbound `json:"outbounds"`
}

type singBoxOutbound struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag"`
	Server     string            `json:"server"`
	ServerPort int               `json:"server_port"`
	Port       int               `json:"port"`
	Password   string            `json:"password"`
	UUID       string            `json:"uuid"`
	Flow       string            `json:"flow"`
	Method     string            `json:"method"`
	Cipher     string            `json:"cipher"`
	Security   string            `json:"security"`
	AlterID    int               `json:"alter_id"`
	Network    string            `json:"network"`
	TLS        *singBoxTLS       `json:"tls"`
	Transport  *singBoxTransport `json:"transport"`
	Obfs       *singBoxObfs      `json:"obfs"`
}

type singBoxTLS struct {
	Enabled    *bool           `json:"enabled"`
	ServerName string          `json:"server_name"`
	Insecure   bool            `json:"insecure"`
	ALPN       []string        `json:"alpn"`
	Reality    *singBoxReality `json:"reality"`
}

type singBoxReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

type singBoxTransport struct {
	Type        string         `json:"type"`
	Path        string         `json:"path"`
	Headers     map[string]any `json:"headers"`
	ServiceName string         `json:"service_name"`
}

type singBoxObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// ParseSingBoxJSON 解析 Sing-box JSON 配置中的节点
func ParseSingBoxJSON(content []byte) ([]*model.Node, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty sing-box json")
	}

	var outbounds []singBoxOutbound

	// 1. 尝试完整配置 {"outbounds": [...]}
	var cfg singBoxConfig
	if err := json.Unmarshal(trimmed, &cfg); err == nil && len(cfg.Outbounds) > 0 {
		outbounds = cfg.Outbounds
	} else {
		// 2. 尝试裸数组 [{...}, {...}]
		if err := json.Unmarshal(trimmed, &outbounds); err != nil {
			return nil, fmt.Errorf("unmarshal sing-box json: %w", err)
		}
	}

	if len(outbounds) == 0 {
		return nil, fmt.Errorf("no outbounds found in sing-box config")
	}

	var nodes []*model.Node
	for _, ob := range outbounds {
		nodeType := strings.ToLower(strings.TrimSpace(ob.Type))
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

		server := strings.TrimSpace(ob.Server)
		port := ob.ServerPort
		if port == 0 {
			port = ob.Port
		}
		if server == "" || port <= 0 {
			continue
		}

		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			tag = fmt.Sprintf("%s-%s:%d", strings.ToUpper(nodeType), server, port)
		}

		var sni string
		var skipCertVerify bool
		var alpn []string
		var realityPubKey string
		var realityShortID string

		if ob.TLS != nil {
			sni = ob.TLS.ServerName
			skipCertVerify = ob.TLS.Insecure
			alpn = ob.TLS.ALPN
			if ob.TLS.Reality != nil {
				realityPubKey = ob.TLS.Reality.PublicKey
				realityShortID = ob.TLS.Reality.ShortID
			}
		}
		if sni == "" && (nodeType == "trojan" || nodeType == "hysteria2" || (ob.TLS != nil && (ob.TLS.Enabled == nil || *ob.TLS.Enabled))) {
			sni = server
		}

		var network string
		var wsPath string
		var wsHeaders map[string]string
		var grpcService string
		if ob.Transport != nil {
			network = strings.ToLower(strings.TrimSpace(ob.Transport.Type))
			if network == "ws" {
				wsPath = ob.Transport.Path
				if len(ob.Transport.Headers) > 0 {
					wsHeaders = make(map[string]string, len(ob.Transport.Headers))
					for k, v := range ob.Transport.Headers {
						switch val := v.(type) {
						case string:
							wsHeaders[k] = val
						case []any:
							if len(val) > 0 {
								wsHeaders[k] = fmt.Sprint(val[0])
							}
						case []string:
							if len(val) > 0 {
								wsHeaders[k] = val[0]
							}
						default:
							wsHeaders[k] = fmt.Sprint(val)
						}
					}
				}
			} else if network == "grpc" {
				grpcService = ob.Transport.ServiceName
			}
		}

		var obfsType string
		var obfsPassword string
		if ob.Obfs != nil {
			obfsType = ob.Obfs.Type
			obfsPassword = ob.Obfs.Password
		}

		method := ob.Method
		if method == "" {
			method = ob.Cipher
		}

		node := &model.Node{
			Tag:            tag,
			Type:           nodeType,
			Server:         server,
			Port:           port,
			Password:       ob.Password,
			SNI:            sni,
			SkipCertVerify: skipCertVerify,
			ALPN:           alpn,
			Network:        network,
			WSPath:         wsPath,
			WSHeaders:      wsHeaders,
			GRPCService:    grpcService,
			UDP:            true,
			UUID:           ob.UUID,
			Flow:           ob.Flow,
			Method:         method,
			AlterID:        ob.AlterID,
			ObfsType:       obfsType,
			ObfsPassword:   obfsPassword,
			RealityPubKey:  realityPubKey,
			RealityShortID: realityShortID,
		}
		nodes = append(nodes, node)
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no supported proxy outbounds found in sing-box config")
	}

	return nodes, nil
}

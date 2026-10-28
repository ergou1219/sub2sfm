package parser

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"sub2sfm/pkg/model"
)

// ParseTrojanURI 解析单个 trojan:// 链接
func ParseTrojanURI(rawURI string) (*model.Node, error) {
	rawURI = strings.TrimSpace(rawURI)
	if !strings.HasPrefix(rawURI, "trojan://") {
		return nil, fmt.Errorf("invalid trojan prefix")
	}

	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("parse trojan url: %w", err)
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" {
		return nil, fmt.Errorf("trojan password missing")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("trojan host missing")
	}

	portStr := u.Port()
	port := 443
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			port = p
		}
	}

	tag := u.Fragment
	if tag != "" {
		if unescaped, err := url.QueryUnescape(tag); err == nil {
			tag = unescaped
		}
	}
	if tag == "" {
		tag = fmt.Sprintf("Trojan-%s:%d", host, port)
	}

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		sni = host
	}

	allowInsecure := q.Get("allowInsecure") == "1" ||
		strings.EqualFold(q.Get("allowInsecure"), "true") ||
		q.Get("insecure") == "1" ||
		strings.EqualFold(q.Get("insecure"), "true")

	network := q.Get("type")
	if network == "" {
		network = q.Get("network")
	}
	if network == "" {
		network = "tcp"
	}

	var wsPath string
	var wsHeaders map[string]string
	if strings.EqualFold(network, "ws") {
		wsPath = q.Get("path")
		if wsPath == "" {
			wsPath = "/"
		}
		wsHost := q.Get("host")
		if wsHost == "" {
			wsHost = sni
		}
		wsHeaders = map[string]string{
			"Host": wsHost,
		}
	}

	var grpcService string
	if strings.EqualFold(network, "grpc") {
		grpcService = q.Get("serviceName")
	}

	var alpn []string
	if rawALPN := q.Get("alpn"); rawALPN != "" {
		for _, a := range strings.Split(rawALPN, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				alpn = append(alpn, a)
			}
		}
	}

	return &model.Node{
		Tag:            tag,
		Type:           "trojan",
		Server:         host,
		Port:           port,
		Password:       password,
		SNI:            sni,
		SkipCertVerify: allowInsecure,
		ALPN:           alpn,
		Network:        network,
		WSPath:         wsPath,
		WSHeaders:      wsHeaders,
		GRPCService:    grpcService,
		UDP:            true,
	}, nil
}

// DecodeBase64 容错解码不同格式与填充的 Base64 字符串
func DecodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")

	// 补齐 padding
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}

	// 尝试标准 Base64
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}

	// 尝试 URL-safe Base64
	if data, err := base64.URLEncoding.DecodeString(s); err == nil {
		return data, nil
	}

	return nil, fmt.Errorf("base64 decode failed")
}

// ParseNodeURI 探测并解析单个节点 URI
func ParseNodeURI(rawURI string) (*model.Node, error) {
	rawURI = strings.TrimSpace(rawURI)
	switch {
	case strings.HasPrefix(rawURI, "trojan://"):
		return ParseTrojanURI(rawURI)
	case strings.HasPrefix(rawURI, "vless://"):
		return ParseVlessURI(rawURI)
	case strings.HasPrefix(rawURI, "hysteria2://"), strings.HasPrefix(rawURI, "hy2://"):
		return ParseHysteria2URI(rawURI)
	case strings.HasPrefix(rawURI, "ss://"):
		return ParseShadowsocksURI(rawURI)
	default:
		return nil, fmt.Errorf("unsupported uri scheme")
	}
}

// ParseVlessURI 解析单个 vless:// 链接
func ParseVlessURI(rawURI string) (*model.Node, error) {
	rawURI = strings.TrimSpace(rawURI)
	if !strings.HasPrefix(rawURI, "vless://") {
		return nil, fmt.Errorf("invalid vless prefix")
	}

	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("parse vless url: %w", err)
	}

	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if uuid == "" {
		return nil, fmt.Errorf("vless uuid missing")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("vless host missing")
	}

	port := 443
	if portStr := u.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	tag := u.Fragment
	if tag != "" {
		if unescaped, err := url.QueryUnescape(tag); err == nil {
			tag = unescaped
		}
	}
	if tag == "" {
		tag = fmt.Sprintf("VLESS-%s:%d", host, port)
	}

	q := u.Query()
	security := strings.ToLower(q.Get("security"))
	sni := q.Get("sni")
	if sni == "" && (security == "reality" || security == "tls") {
		sni = host
	}

	allowInsecure := q.Get("allowInsecure") == "1" ||
		strings.EqualFold(q.Get("allowInsecure"), "true") ||
		q.Get("insecure") == "1" ||
		strings.EqualFold(q.Get("insecure"), "true")

	var alpn []string
	if rawALPN := q.Get("alpn"); rawALPN != "" {
		for _, a := range strings.Split(rawALPN, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				alpn = append(alpn, a)
			}
		}
	}

	network := q.Get("type")
	if network == "" {
		network = q.Get("network")
	}
	if network == "" {
		network = "tcp"
	}

	var wsPath string
	var wsHeaders map[string]string
	if strings.EqualFold(network, "ws") {
		wsPath = q.Get("path")
		if wsPath == "" {
			wsPath = "/"
		}
		wsHost := q.Get("host")
		if wsHost == "" {
			wsHost = q.Get("headerType")
		}
		if wsHost != "" {
			wsHeaders = map[string]string{"Host": wsHost}
		}
	}

	var grpcService string
	if strings.EqualFold(network, "grpc") {
		grpcService = q.Get("serviceName")
	}

	return &model.Node{
		Tag:            tag,
		Type:           "vless",
		Server:         host,
		Port:           port,
		UUID:           uuid,
		Flow:           q.Get("flow"),
		SNI:            sni,
		SkipCertVerify: allowInsecure,
		Network:        network,
		ALPN:           alpn,
		WSPath:         wsPath,
		WSHeaders:      wsHeaders,
		GRPCService:    grpcService,
		RealityPubKey:  q.Get("pbk"),
		RealityShortID: q.Get("sid"),
		UDP:            true,
	}, nil
}

// ParseHysteria2URI 解析单个 hysteria2:// 或 hy2:// 链接
func ParseHysteria2URI(rawURI string) (*model.Node, error) {
	rawURI = strings.TrimSpace(rawURI)
	if !strings.HasPrefix(rawURI, "hysteria2://") && !strings.HasPrefix(rawURI, "hy2://") {
		return nil, fmt.Errorf("invalid hysteria2 prefix")
	}

	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("parse hysteria2 url: %w", err)
	}

	password := ""
	if u.User != nil {
		if pwd, ok := u.User.Password(); ok {
			password = u.User.Username() + ":" + pwd
		} else {
			password = u.User.Username()
		}
	}
	if password == "" {
		return nil, fmt.Errorf("hysteria2 password missing")
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("hysteria2 host missing")
	}

	port := 443
	if portStr := u.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	tag := u.Fragment
	if tag != "" {
		if unescaped, err := url.QueryUnescape(tag); err == nil {
			tag = unescaped
		}
	}
	if tag == "" {
		tag = fmt.Sprintf("HY2-%s:%d", host, port)
	}

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = host
	}

	allowInsecure := q.Get("allowInsecure") == "1" ||
		strings.EqualFold(q.Get("allowInsecure"), "true") ||
		q.Get("insecure") == "1" ||
		strings.EqualFold(q.Get("insecure"), "true")

	var alpn []string
	if rawALPN := q.Get("alpn"); rawALPN != "" {
		parts := strings.Split(rawALPN, ",")
		for _, part := range parts {
			p := strings.TrimSpace(part)
			if p != "" {
				alpn = append(alpn, p)
			}
		}
	}

	return &model.Node{
		Tag:            tag,
		Type:           "hysteria2",
		Server:         host,
		Port:           port,
		Password:       password,
		SNI:            sni,
		SkipCertVerify: allowInsecure,
		ALPN:           alpn,
		ObfsType:       q.Get("obfs"),
		ObfsPassword:   q.Get("obfs-password"),
		UDP:            true,
	}, nil
}

// ParseShadowsocksURI 解析单个 ss:// 链接 (SIP002 或 Legacy Base64)
func ParseShadowsocksURI(rawURI string) (*model.Node, error) {
	rawURI = strings.TrimSpace(rawURI)
	if !strings.HasPrefix(rawURI, "ss://") {
		return nil, fmt.Errorf("invalid shadowsocks prefix")
	}

	rest := rawURI[5:]
	tag := ""
	if idx := strings.Index(rest, "#"); idx != -1 {
		rawTag := rest[idx+1:]
		if unescaped, err := url.QueryUnescape(rawTag); err == nil {
			tag = unescaped
		} else {
			tag = rawTag
		}
		rest = rest[:idx]
	}

	if idx := strings.Index(rest, "?"); idx != -1 {
		rest = rest[:idx]
	}
	rest = strings.TrimSuffix(rest, "/")

	var method, password, host string
	var port int

	if strings.Contains(rest, "@") {
		parts := strings.SplitN(rest, "@", 2)
		userInfo := parts[0]
		hostPort := parts[1]

		if decodedUser, err := DecodeBase64(userInfo); err == nil {
			userInfo = string(decodedUser)
		}
		userParts := strings.SplitN(userInfo, ":", 2)
		if len(userParts) == 2 {
			method = userParts[0]
			password = userParts[1]
		} else {
			password = userInfo
		}

		h, pStr, err := net.SplitHostPort(hostPort)
		if err == nil {
			host = h
			port, _ = strconv.Atoi(pStr)
		} else {
			host = hostPort
			port = 8388
		}
	} else {
		decoded, err := DecodeBase64(rest)
		if err != nil {
			return nil, fmt.Errorf("decode shadowsocks uri: %w", err)
		}
		decodedStr := string(decoded)
		lastAt := strings.LastIndex(decodedStr, "@")
		if lastAt == -1 {
			return nil, fmt.Errorf("invalid shadowsocks payload: %s", decodedStr)
		}
		userInfo := decodedStr[:lastAt]
		hostPort := decodedStr[lastAt+1:]
		userParts := strings.SplitN(userInfo, ":", 2)
		if len(userParts) == 2 {
			method = userParts[0]
			password = userParts[1]
		}
		h, pStr, err := net.SplitHostPort(hostPort)
		if err == nil {
			host = h
			port, _ = strconv.Atoi(pStr)
		} else {
			host = hostPort
			port = 8388
		}
	}

	if host == "" || port <= 0 {
		return nil, fmt.Errorf("invalid shadowsocks server or port")
	}
	if tag == "" {
		tag = fmt.Sprintf("SS-%s:%d", host, port)
	}

	return &model.Node{
		Tag:      tag,
		Type:     "shadowsocks",
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
		UDP:      true,
	}, nil
}

// ParseTrojanBase64 解析 Base64 编码的多行节点列表
func ParseTrojanBase64(content string) ([]*model.Node, error) {
	decoded, err := DecodeBase64(content)
	if err != nil {
		return nil, err
	}
	return ParseNodeLines(string(decoded))
}

// ParseNodeLines 解析多行包含协议链接的文本
func ParseNodeLines(text string) ([]*model.Node, error) {
	lines := strings.Split(text, "\n")
	var nodes []*model.Node
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "trojan://") ||
			strings.HasPrefix(line, "vless://") ||
			strings.HasPrefix(line, "hysteria2://") ||
			strings.HasPrefix(line, "hy2://") ||
			strings.HasPrefix(line, "ss://") {
			node, err := ParseNodeURI(line)
			if err == nil && node != nil {
				nodes = append(nodes, node)
			}
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no valid proxy nodes found")
	}
	return nodes, nil
}

// ParseTrojanLines 解析多行包含代理链接的文本 (向前兼容)
func ParseTrojanLines(text string) ([]*model.Node, error) {
	return ParseNodeLines(text)
}

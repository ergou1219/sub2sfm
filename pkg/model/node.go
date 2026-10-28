package model

// Node 表示统一的代理节点模型（以 Trojan 协议为核心）
type Node struct {
	Tag            string            `json:"tag"`
	Type           string            `json:"type"` // trojan, vless, hysteria2, shadowsocks, vmess
	Server         string            `json:"server"`
	Port           int               `json:"port"`
	Password       string            `json:"password,omitempty"`
	SNI            string            `json:"sni,omitempty"`
	SkipCertVerify bool              `json:"skip_cert_verify,omitempty"`
	ALPN           []string          `json:"alpn,omitempty"`
	Network        string            `json:"network,omitempty"` // tcp, ws, grpc
	WSPath         string            `json:"ws_path,omitempty"`
	WSHeaders      map[string]string `json:"ws_headers,omitempty"`
	GRPCService    string            `json:"grpc_service,omitempty"`
	UDP            bool              `json:"udp"`
	UUID           string            `json:"uuid,omitempty"`
	Flow           string            `json:"flow,omitempty"`
	Method         string            `json:"method,omitempty"`
	AlterID        int               `json:"alter_id,omitempty"`
	Up             string            `json:"up,omitempty"`
	Down           string            `json:"down,omitempty"`
	ObfsType       string            `json:"obfs_type,omitempty"`
	ObfsPassword   string            `json:"obfs_password,omitempty"`
	RealityPubKey  string            `json:"reality_pubkey,omitempty"`
	RealityShortID string            `json:"reality_short_id,omitempty"`
}

// ConvertOptions 包含配置生成的定制选项
type ConvertOptions struct {
	Preset        string // "geek" (默认), "standard", "global"
	SSHMode       string // "direct" (默认), "proxy"
	WebRTCMode    string // "block" (默认), "direct", "proxy"
	CustomRules   string // 形如 domain:example.com=direct,port:2222=SSH出口,geosite:netflix=proxy,geoip:us=direct
	AllowInsecure bool   // 允许不安全/已过期 TLS 证书
	EnableIPv6    bool   // 启用 TUN/Fake-IP 双栈，默认关闭以规避无全局 IPv6 时的连接重置
	RuleCDN       bool   // 启用 jsDelivr CDN 加速规则集下载（规避 GitHub 无法访问问题）
}

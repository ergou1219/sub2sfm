package parser

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sub2sfm/pkg/model"
)

var defaultClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

// FetchSubscription 从远程 URL 获取订阅内容
func FetchSubscription(ctx context.Context, subURL string, userAgent string) ([]byte, error) {
	if cached, ok := defaultCache.Get(subURL); ok {
		return cached, nil
	}

	if userAgent == "" {
		userAgent = "ClashMeta; sing-box; sub2sfm/1.0"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription response status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	defaultCache.Set(subURL, body)
	return body, nil
}

func hasSupportedURIScheme(s string) bool {
	return strings.Contains(s, "trojan://") ||
		strings.Contains(s, "vless://") ||
		strings.Contains(s, "hysteria2://") ||
		strings.Contains(s, "hy2://") ||
		strings.Contains(s, "ss://")
}

// Parse 自动探测并解析不同格式的订阅数据
func Parse(content []byte) ([]*model.Node, error) {
	trimmed := bytes.TrimSpace(content)
	str := string(trimmed)

	// 1. 直接包含协议 URI 前缀
	if hasSupportedURIScheme(str) {
		nodes, err := ParseNodeLines(str)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 2. 含有 proxies: 关键字，可能是 Clash YAML
	if strings.Contains(str, "proxies:") {
		nodes, err := ParseClashYAML(trimmed)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 3. 尝试 Base64 解码
	decoded, err := DecodeBase64(str)
	if err == nil {
		decodedStr := string(decoded)
		if hasSupportedURIScheme(decodedStr) {
			nodes, err := ParseNodeLines(decodedStr)
			if err == nil && len(nodes) > 0 {
				return nodes, nil
			}
		}
		if strings.Contains(decodedStr, "proxies:") {
			nodes, err := ParseClashYAML(decoded)
			if err == nil && len(nodes) > 0 {
				return nodes, nil
			}
		}
	}

	// 4. 最后兜底尝试 YAML
	if nodes, err := ParseClashYAML(trimmed); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	return nil, fmt.Errorf("unknown subscription format or no supported nodes found")
}

// ParseFromInput 处理 URL 或直接文本内容
func ParseFromInput(ctx context.Context, input string) ([]*model.Node, error) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		data, err := FetchSubscription(ctx, input, "")
		if err != nil {
			return nil, err
		}
		return Parse(data)
	}
	return Parse([]byte(input))
}

# sub2sfm: 机场订阅转 Sing-box (SFM) 转换器

专为 macOS 上的 SFM (Sing-box for Mac) 优化的轻量订阅转换服务。彻底解决 SSH 频繁断连、DNS 泄漏与 WebRTC 暴露问题。原生支持 Trojan、VLESS (Reality)、Hysteria 2、Shadowsocks 与 VMess。

## 核心特性

1. **防 SSH 断连 TUN 架构**：
   - macOS NetworkExtension 强制 `stack: "mixed"`（TCP 走 gVisor 用户态协议栈，UDP 直通），彻底免疫系统 socket 空闲重置问题。
   - `mtu: 1500`（替代旧版的 9000 巨帧），杜绝 PMTU 分片包黑洞丢失。
   - 独立 `SSH出口` 策略组（默认直连，亦可一键切换为代理出口）。
2. **零 DNS 泄漏分流**：
   - 修复规则匹配优先级，国内域名（`geosite-cn`）优先直连解析，境外域名走 Fake-IP / 代理。
   - 彻底移除旧版会导致向阿里 DNS 明文泄露所有 Fake-IP 域名的 `action: resolve` 操作。
   - 拦截 Type 65 (HTTPS) DNS 查询，阻断 Apple / Chrome ECH 绕过。
3. **WebRTC 防护**：
   - 全面拦截 STUN/TURN 协议端口（3478, 5349, 19302-19309）与域名，杜绝浏览器 WebRTC 探测暴露真实公网 IP。
4. **多协议与 Reality 适配**：
   - 原生支持 Trojan、VLESS (含 Reality uTLS 指纹)、Hysteria 2、Shadowsocks 与 VMess 节点。
   - 兼容 Clash YAML、Base64 以及协议 URI（`trojan://`、`vless://`、`hysteria2://`、`ss://` 等）单行或多行文本。
5. **自定义分流规则**：
   - 支持通过 Web UI 或 URL 参数随时追加私有分流规则（支持 `domain:` / `suffix:` / `keyword:` / `ip:` / `port:` / `geosite:` / `geoip:`），优先匹配。
6. **极简内嵌 Web UI & 内存缓存**：
   - 单二进制文件，内嵌原生 Web UI，零外部 CDN 依赖，支持一键复制 SFM 订阅链接与一键调起 SFM 导入。
   - 内置带 5 分钟 TTL 的内存订阅缓存，避免频繁转换对机场源站造成请求穿透。

## 快速使用

### 1. 运行服务
```bash
go run main.go -port 8080
```
或编译为单可执行二进制：
```bash
go build -o sub2sfm main.go
./sub2sfm -port 8080
```

### 2. 容器化运行 (Docker & Docker Compose)

**使用 Docker Compose 启动（推荐）：**
```bash
docker compose up -d
```

**使用 Docker 原生命令构建并启动：**
```bash
docker build -t sub2sfm .
docker run -d --name sub2sfm -p 8080:8080 -e PORT=8080 sub2sfm
```
> 提示：服务默认监听 `0.0.0.0:8080`，可通过设置 `HOST` 与 `PORT` 环境变量或启动参数自定义监听地址。

### 3. 访问 Web 界面
浏览器打开 `http://127.0.0.1:8080`，输入机场订阅链接即可生成 SFM 订阅。

### 4. API 参数说明
订阅地址示例：
```
http://127.0.0.1:8080/sub?sub=https://airport.com/subscribe&preset=geek&ssh=direct&rules=domain:myvps.com=direct,port:2222=SSH出口,geosite:netflix=proxy
```
- `sub` / `url`：原机场订阅链接（支持 Clash YAML、Base64，以及 `trojan://`、`vless://`、`hysteria2://` / `hy2://`、`ss://` 等链接）。
- `preset`：分流预设，可选 `geek`（默认分流，含 OpenAI/GitHub/国内直连）、`standard`（轻量分流）、`global`（全局代理）。
- `ssh`：SSH 默认出口，可选 `direct`（默认，全局直连）或 `proxy`（走节点选择）。
- `webrtc`：WebRTC 防护，可选 `block`（默认，全局拦截）、`direct`、`proxy`。
- `ipv6`：IPv6 开关，默认关闭（TUN/Fake-IP/DNS 只走 IPv4）；传 `on` 恢复双栈。
- `insecure` / `allow_insecure`：允许不安全/已过期/自签名 TLS 证书，传 `true` / `on` / `1` 开启。
- `cdn` / `rule_cdn`：规则集走 jsDelivr CDN 加速（避免 GitHub 直连网络受阻），传 `true` / `on` / `1` 开启。
- `refresh` / `nocache`：强制刷新服务端内存订阅缓存，传 `true` / `on` / `1` 触发重新抓取。
- `rules`：自定义分流规则，如 `domain:myvps.com=direct,port:2222=SSH出口,geosite:netflix=proxy,geoip:us=direct`。`geosite` / `geoip` 的名字对应 SagerNet 规则集。

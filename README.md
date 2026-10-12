# Telegram WEB · 翼龙 Python 面板上传包

启动文件是 **main.py**。需要填写的变量全部在 **config.json**，启动时自动读取，全程不询问输入。

这是 Python 启动器＋Telegram 官方 Go WEB 中继＋Python MTProxy 后端的组合，**不是纯 Python 重写 WEB 协议**。Go 组件第一次启动会自动下载工具链并编译。不要运行项目教程里的 Docker 命令；面板已经是一个受管理的容器。

本包按你选择的 **Cloudflare 普通代理＋回源端口规则** 制作，**不使用 Cloudflare Tunnel**，也不需要再租第二台服务器。

## 你这次的流量路径

```text
手机 / 电脑上的 Telegram
        ↓ HTTPS，公网 443
Cloudflare 橙云代理
        ↓ HTTPS，回源端口改成你的随机公网端口
翼龙面板分配的端口
        ↓ 本包的 HTTPS 接收程序
官方 tproxy-server（仅本机内部端口）
        ↓
Python MTProxy（仅本机内部端口）
        ↓ 主动连接出去
Telegram 服务器
```

Cloudflare 的 443 和你机器的随机端口可以不同。你添加的 A 记录，是告诉 Cloudflare 机器的公网 IPv4；**橙云使它代收请求，回源端口规则告诉它转到哪个端口**。仅添加 A 记录不会自动改端口。

## 1. 上传和填写配置

把压缩包解压后的所有文件、文件夹上传到面板文件根目录。文件根目录下应直接有 `main.py`、`config.json`、`run_backend.py`、`front/`、`public/`。不要只上传 main.py。

打开 `config.json`，主要改这两项：

```json
"domain": "tg.你的域名.com",
"listen_port": 23456
```

上面的 23456 必须替换成自己的端口。也可以保持 `listen_port: 0`，程序会依次读取面板的 `SERVER_PORT`、`PORT` 环境变量；两个都没有时会给出明确提示，不会乱选端口。

如果商家做了“公网端口 → 容器内部端口”的映射，这里填**内部监听端口**，下面 Cloudflare 规则填**公网端口**。常见翼龙分配中二者相同，但以面板提供的信息为准。

`secret` 留空，首次启动会自动生成并保存在 `.runtime/generated-secret.txt`，以后重启不会改变。也可自己填 32 位十六进制密钥。不要沿用教程里公开的示例密钥。

## 2. Cloudflare 设置（必须完成）

使用一个专用子域名，例如 `tg.example.net`。

1. **DNS → 添加 A 记录**：名称填 `tg`，IPv4 填商家给你的**公网 IPv4**，打开**橙云 / 已代理**。不要填面板管理网页的 IP，也不要填容器内网 IP。不要添加一个指向其它入口的 AAAA 记录。
2. **规则 → 源站规则 / Origin Rules → 创建规则**：匹配条件是 `Hostname equals tg.example.net`，对应表达式 `(http.host eq "tg.example.net")`。动作选择 **Destination port / 目标端口 / 回源端口 → 重写为你的随机公网端口**，例如 `23456`。只改端口，保留原始 Host，不要建立网页 301/302 跳转。
3. **SSL/TLS 模式**：默认配置 `tls.mode=self_signed` 会自动生成回源证书，对应 Cloudflare 的 **Full / 完全**。不是 Flexible，也不是 Full (strict)。如果该区域已有网站且正在使用 Full (strict)，建议采用下一节的 Origin CA 证书方法，保持原有严格验证；不要为了本子域名降低其它网站的设置。
4. 给这个子域名建立 **Cache Rule：Bypass cache / 绕过缓存**。不要缓存桥接页面及 API。保持 WebSockets 功能开启。
5. 这个子域名不要套 Cloudflare Access 登录页、Under Attack 挑战页或会拦截请求的人机验证。不要对桥接页面启用 Rocket Loader、脚本重写和 Email Obfuscation。修改尽量仅作用于这个子域名。

**无需 Cloudflare API Token。程序不会代你修改 Cloudflare 账户设置。**

只要入口仍然使用域名的 443，Cloudflare 的回源端口规则可以把目标改为 1–65535 中的端口。这里传的是 HTTPS / WebSocket，与你直接用普通 MTProxy TCP 连接 Cloudflare 不是一回事。

### 可选：保持 Full (strict)

在 Cloudflare 的 SSL/TLS → Origin Server 创建覆盖该子域名的 Origin CA 证书。保存为 `origin.pem` 和 `origin.key` 并上传到 main.py 同目录，然后把配置改成：

```json
"tls": {
  "mode": "provided",
  "cert_file": "origin.pem",
  "key_file": "origin.key"
}
```

这时 Cloudflare 可以使用 **Full (strict)**。证书需要与域名匹配且未过期；私钥文件不要放进 `public/`。Full 会加密回源连接但不校验证书身份，Full (strict) 会验证。

## 3. 在翼龙面板启动

- Python 版本建议 3.10、3.11 或 3.12；机器架构支持 Linux x86_64、ARM64。
- 启动文件选择 `main.py`。如果面板允许填写命令，使用 `python -u main.py`。
- 若面板自动安装 requirements.txt，保留该文件即可；程序也会尝试在本目录安装加速依赖。
- 点击启动，等待首次下载和编译完成。会输出进度，无须键盘输入。建议至少 1 GB 内存、1 GB 可用磁盘；首次编译的资源开销高于日常运行，配额不足时需要增加资源。
- 出站需能访问 GitHub API / codeload、Go 下载站和 Go 模块服务；运行时需能主动连接 Telegram。面板必须允许 Python 创建子进程并执行本目录中的 Linux 程序。

首次启动只在上传目录内准备组件，不需要 root、apt、systemd 或 Docker。Go 下载包有 SHA-256 校验；两份上游源码在首次运行时解析到具体 Git 提交，并写入 `.runtime/components.lock.json`，后续重启不会自动追踪上游最新代码。首次解析的版本仍是首次运行当时的上游版本，而不是交付时已经完成联调的固定版本。

第一次的编译产物、源码和工具链会缓存到 `.runtime/`。不要每次启动都删除这个目录，否则会重复下载编译，也可能丢失自动生成的密钥。程序异常退出最多重试 5 次；面板发出 SIGTERM / SIGINT 时会停止子进程。

## 4. 在 Telegram 中连接

启动后在面板文件管理器打开 **proxy-link.txt**，复制其中的 WEB 代理链接到支持 WEB 模式的 Telegram 客户端中打开，并选择连接。也可手动选择 WEB 类型，填写域名和密钥。不要把随机端口加到 Telegram 的域名后面。

如果 `https://t.me/webproxy?...` 网页不能正确交给客户端，可使用文件里的 `tg://webproxy?...` 链接。是否支持取决于客户端版本。

日志会分别报告：

- **本机组件已启动**：只确认本机进程和监听端口就绪。
- **公网 HTTPS 已回到本进程**：证实访问该域名能经过 Cloudflare 回到这个运行实例。
- 最后仍需在 Telegram 中确认可以收发消息、加载媒体。这两条启动日志不代表 Telegram 协议已通过实测。

默认不在日志打印包含密钥的链接，文件管理器中读取即可。需要在面板控制台显示时，设置 `show_link_in_console: true`。

## 配置项

| 配置 | 说明 |
| --- | --- |
| domain | 自己的子域名，只填名称，不带协议、端口、路径 |
| listen_port | 面板内部监听端口；0 自动读取 SERVER_PORT 或 PORT |
| secret | 留空生成并持久保存；或自行填 32 位十六进制，可带 dd 前缀 |
| carrier_mode | 默认 websocket；可选 https、https-lanes、websocket-lanes |
| tls.mode | self_signed 自动生成回源证书；provided 使用上传的 PEM 文件 |
| tls.cert_file / key_file | provided 模式才使用，路径相对 main.py 所在目录 |
| install_python_dependencies | 是否自动尝试安装 cryptography 加速；失败会用上游的纯 Python AES |
| check_public_entry | 是否定期检查自己的域名是否回到当前实例 |
| show_link_in_console | 是否在控制台打印包含密钥的连接链接，默认 false |

修改配置后在面板重启。请先把 `public/index.html` 换成你自己的普通网站首页；只有 `public/` 会作为静态网站公开，`.runtime/`、配置和证书不会作为静态文件提供。

## 常见问题

| 现象 | 先检查什么 |
| --- | --- |
| 启动后提示填写域名或端口 | 改 config.json；端口 0 需要面板提供环境变量 |
| Cloudflare 521 / 522 | 程序是否监听、A 记录是否正确、回源端口是否是公网分配端口、商家是否放通 |
| Cloudflare 525 | 回源必须连到本包 HTTPS 端口，不能误指向其它 HTTP 服务 |
| Cloudflare 526 | 正在用严格模式却没有有效 Origin CA / 公共证书；按 provided 方式配置 |
| 域名能打开，但 Telegram 连接中 | 客户端是否支持 WEB、密钥是否一致、是否有挑战页或缓存、WebSockets 是否可用、服务器能否访问 Telegram |
| WebSocket 不稳定 | 检查 Cloudflare WebSockets 设置；也可在配置中改 carrier_mode 为 https 后重启测试 |
| Permission denied / Exec format error | 面板是否允许执行本地程序，是否 Linux x86_64 或 ARM64 |
| 编译退出 137 / killed | 通常是面板内存配额不足；增加资源后重新启动 |
| 橙云回源一直 404 | 确认 Host 未被改写、请求到达正确实例；商家若把来源 IP 全部改成私有网关地址，本包的 Cloudflare 来源校验会拒绝，需要针对商家实际拓扑调整，不能盲目信任所有 IP |

本包的公网接收程序只接受 Cloudflare 官方网段和本机检查，按你的选择专用于普通 Cloudflare 代理。它不会为任意客户端提供通用 HTTP 代理，也不会连接用户任意指定的后端地址。

## 验证情况与限制

交付前在 Python 3.12 下通过了 13 项启动器测试，覆盖配置端口、密钥持久性、私有目录隔离、归档路径检查和子进程终止等。

`front/main_test.go` 包含 HTTP 请求头、二进制转发、WebSocket 双向通道及证书生成测试。第一次面板编译时自动运行这些测试，失败则停止构建；**交付环境未运行 Go 测试，也未完成真实 Telegram / Cloudflare / 翼龙面板端到端联调**。

本地下载官方源码的自动审批服务返回 404（审批模型不受支持），因此没有在此环境完成组件下载与实际编译。文件已完成源码级检查和上述 Python 测试；没有将“尚未验证”写成“已可用”。上游 WEB 协议本身仍在实验阶段。

## 参考来源

- [Telegram 官方 tproxy-server](https://github.com/telegramdesktop/tproxy-server)
- [官方 WEB 协议](https://github.com/telegramdesktop/tproxy-server/blob/master/PROTOCOL.md)
- [Python MTProxy 后端](https://github.com/alexbers/mtprotoproxy)
- [ellermister 的 WEB / Cloudflare 配置说明](https://github.com/ellermister/mtproxy/blob/master/docs/parameters.md)
- [Cloudflare 目标端口规则](https://developers.cloudflare.com/rules/origin-rules/features/#destination-port)
- [Cloudflare Full 模式](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full/)

本包没有复制分发两份上游实现；首次启动从各自官方仓库下载。上游代码保留原始许可证和文件。启动器和 front/ 的代码见本包 LICENSE。

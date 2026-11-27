# route-rules for Xiaomi BE7000

为小米 BE7000 的 ARM64 OpenWrt 生成代理配置、DNS 和 nftables 规则以及接入脚本。此分支复用五平台客户端的规则编译器，从同次构建生成的 Linux 配置与 SRS 派生路由器配置。

## 功能

- mosdns 使用域名直连和拒绝集合来选择上游或返回 `REFUSED`。
- nftables 按 IPv4 和端口分类，匹配拒绝的连接主动回包，匹配直连的连接由 fw4 转发，剩余流量交给 sing-box。
- 构建和运行以两个核心仓库的公开 0.0.2 Release 为基线，并使用 `ctmark-v1` 连接判定缓存。项目接入范围见[设置归属](openwrt/docs/USER-SETTING-OWNERSHIP.md)。

## 快速开始

1. 从 [GitHub Releases](https://github.com/lyleee0083/route-rules/releases) 或 [GitHub Actions](https://github.com/lyleee0083/route-rules/actions/workflows/be7000.yml) 下载 `route-rules-xiaomi-be7000-v<版本>.zip` 和 `SHA256SUMS.txt`，核对 ZIP。
2. 在私有目录解压 ZIP。在 `config.json` 的 `proxy` 出站填写自己的 VLESS REALITY 节点，并更新包内 `SHA256SUMS` 中 `config.json` 的摘要。
3. 目标需要 ARM64 OpenWrt、fw4、nftables 和可用的 TUN。从 [sing-box 0.0.2](https://github.com/lyleee0083/xiaomi-be7000-singbox/releases/tag/sing-box-xiaomi-be7000-0.0.2) 和 [MosDNS 0.0.2](https://github.com/lyleee0083/xiaomi-be7000-mosdns/releases/tag/mosdns-xiaomi-be7000-0.0.2) 下载 ARM64 核心，分别按 `/usr/bin/sing-box` 和 `/usr/bin/mosdns` 安装为可执行文件。安装脚本会校验两个核心的 SHA-256。全新安装与激活入口分别为 `sh install.sh --install-authorized` 和 `sh activate.sh --activate-authorized`。已有安装应先按对应版本的迁移流程核对，安装程序会拒绝覆盖。

在解压目录配置完节点后，用下列命令更新配置摘要，并核验整个载荷。

```sh
set -e
config_sum=$(sha256sum config.json)
awk -v replacement="$config_sum" '
  $2 == "config.json" { print replacement; count++; next }
  { print }
  END { if (count != 1) exit 1 }
' SHA256SUMS > SHA256SUMS.new
mv SHA256SUMS.new SHA256SUMS
sha256sum -c SHA256SUMS
```

## 配置

上游规则和公开母版位于 [客户端规则来源清单](https://github.com/lyleee0083/route-rules/blob/d1a3bd6041c5ce7467253f6dd62bc06e025d7497/routing/routing-sources.json) 和 [配置母版](https://github.com/lyleee0083/route-rules/blob/d1a3bd6041c5ce7467253f6dd62bc06e025d7497/config/sing-box-core-base.json)。CI 使用示例节点，填写后的配置请在本地保管。

## 构建与测试

[BE7000 工作流](.github/workflows/be7000.yml)在 `ubuntu-latest` 将本分支的 OpenWrt 源码与从 [main 的固定提交](https://github.com/lyleee0083/route-rules/commit/d1a3bd6041c5ce7467253f6dd62bc06e025d7497) 取出的规则、配置和编译器放入独立构建目录，然后运行 Go 控制器与 shell 回归测试，只生成所需的 Linux 客户端快照、生成 MosDNS JSON 配置并编译 `.mdrs` 域名规则，再派生 nftables 策略、交叉构建 ARM64 控制器并核对整个 ZIP。CI 还在本机环回中验证 MosDNS 行为。更新共享源码时，在工作流中修改 `ROUTE_RULES_MAIN_REVISION`，并重新运行 BE7000 测试。真实路由器的启动、nftables 接管与 LAN 转发需另行验收。

## 仓库结构

- `openwrt/scripts/` 处理 Linux 快照、策略转换和打包。
- `openwrt/src/controller/` 为 OpenWrt 控制器，`openwrt/src/native/` 为 nftables 和服务接入源码。
- `openwrt/tests/` 验证配置、打包、控制器、shell 与 DNS 行为。

## 版本发布

发布资产包含配置 ZIP 和 `SHA256SUMS.txt`。ZIP 内的 `SHA256SUMS` 供安装、控制器和回滚逐项校验。ZIP 内为配置、规则、ARM64 控制器和接入脚本。两个核心由各自的仓库发布，回滚保留其已安装的文件。BE7000 提交、共享的 `main` 提交、规则输入与双核心校验值记录在 Actions 构建信息工件。

## 许可证

共享规则与 sing-box 的许可证见 [main 的第三方来源](https://github.com/lyleee0083/route-rules/blob/d1a3bd6041c5ce7467253f6dd62bc06e025d7497/docs/THIRD-PARTY.md)。MosDNS 0.0.2 的上游许可见 [MosDNS v5 源码及许可证](https://github.com/IrineSistiana/mosdns/tree/9cfb7ce985599c087cb7ccfb1531d0c0f4021242)。

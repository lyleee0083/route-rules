# route-rules

为 Windows、Linux、macOS、Android 和 iOS 生成 sing-box TUN 配置和共享规则集。小米 BE7000 的 OpenWrt 运行包由 [`xiaomi-be7000` 分支](https://github.com/lyleee0083/route-rules/tree/xiaomi-be7000) 构建。

## 功能

- 合并源清单中的静态和远程规则，按域名、IPv4、端口分别计算优先级，再编译本地二进制 SRS。
- 域名用于 DNS 分组和拒绝。业务按 IPv6 拒绝、IPv4 或端口拒绝、有效直连规则的顺序处理，其余交给 `proxy`。

## 快速开始

1. 从 [GitHub Releases](https://github.com/lyleee0083/route-rules/releases) 下载 `route-rules-clients-v<版本>.zip` 和 `SHA256SUMS.txt`，对照 `SHA256SUMS.txt` 核对 ZIP。
2. 解压 ZIP，选择对应平台的 `sing-box-*.json`。保留同目录下的 `rule-set/`。
3. 在本地填写 `outbounds` 中 `tag` 为 `proxy` 的 VLESS REALITY 节点。构建包使用示例地址、UUID、公钥和短 ID。使用 sing-box 1.14.4 或支持 SRS v5 的兼容核心加载配置。

## 配置

- [公共配置母版](config/sing-box-core-base.json)维护 TUN、DNS 和出站，[平台配置](config/client-profiles.json)维护各平台差异。
- [规则来源清单](routing/routing-sources.json)维护 AdGuard DNS、V2Ray DAT、Mihomo MRS/Clash YAML、纯文本 CIDR 和 dnsmasq 输入，以及静态 JSON 的优先级。
- 真实节点配置只填在本地。把修改后的文件保存在 Git 工作区外，或命名为 `*.local.json`。

## 构建与测试

[客户端工作流](.github/workflows/clients.yml)在 GitHub Actions 的 ubuntu-latest 下载并校验固定的 sing-box 1.14.4、刷新规则、运行规则与归档测试、生成五平台 ZIP，再解码检查交付的 SRS。推送 `main`、向 `main` 提交 PR 或手动运行均会触发。每次构建的输入 URL 和内容 SHA-256 单独记录在 Actions 构建信息工件。客户端 CI 验证覆盖规则与配置，实际平台 TUN 和节点连通性由设备验收确认。

## 仓库结构

- `config/` 配置母版和平台差异。
- `routing/` 规则来源清单和静态规则。
- `scripts/`、`src/` 生成入口和规则编译实现。
- `tests/` 回归测试。

## 版本发布

`VERSION` 对应交付版本。客户端交付包含配置 ZIP 和 `SHA256SUMS.txt`。ZIP 内包含五份配置和它们引用的本地 SRS。

## 许可证

各上游规则与核心沿用其上游条款，来源及核对版本见[第三方来源](docs/THIRD-PARTY.md)。

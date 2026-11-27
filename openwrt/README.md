# route-rules for Xiaomi BE7000

为小米 BE7000 的 ARM64 OpenWrt 生成 sing-box、mosdns 和 nftables 运行包。此分支复用五平台客户端的规则编译器，从同次构建生成的 Linux 配置与 SRS 派生路由器配置。

## 功能

- mosdns 使用域名直连和拒绝集合来选择上游或返回 `REFUSED`。
- nftables 按 IPv4 和端口分类，匹配拒绝的连接主动回包，匹配直连的连接由 fw4 转发，剩余流量交给 sing-box。
- 构建固定 sing-box 1.14.4 和 mosdns 5.3.4，并使用 `ctmark-v1` 连接判定缓存。项目接入范围见[设置归属](docs/USER-SETTING-OWNERSHIP.md)。

## 快速开始

1. 从 [Xiaomi BE7000 工作流](https://github.com/lyleee0083/route-rules/actions/workflows/be7000.yml) 的成功运行下载 `route-rules-xiaomi-be7000-v<版本>`，按 `SHA256SUMS.txt` 核对内部 ZIP。
2. 在私有目录解压内部 ZIP。在 `config.json` 的 `proxy` 出站填写自己的 VLESS REALITY 节点，并更新包内 `SHA256SUMS` 中 `config.json` 的摘要。
3. 目标需要 ARM64 OpenWrt、fw4、nftables 和可用的 TUN。全新安装与激活入口分别为 `sh install.sh --install-authorized` 和 `sh activate.sh --activate-authorized`。已有安装应先按对应版本的迁移流程核对，安装程序会拒绝覆盖。

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

上游规则和公开母版位于 [客户端规则来源清单](../routing/routing-sources.json) 和 [配置母版](../config/sing-box-core-base.json)。CI 使用示例节点，填写后的配置请在本地保管。

## 构建与测试

[BE7000 工作流](../.github/workflows/be7000.yml)在 ubuntu-latest 运行 Go 控制器与 shell 回归测试，生成 Linux 客户端快照、派生 mosdns 和 nftables 策略、交叉构建 ARM64 控制器并核对整个 ZIP。CI 还在本机环回中验证 mosdns 行为。真实路由器的启动、nftables 接管与 LAN 转发需另行验收。

## 仓库结构

- `scripts/` 处理 Linux 快照、策略转换和打包。
- `src/controller/` 为 OpenWrt 控制器，`src/native/` 为 nftables 和服务接入源码。
- `tests/` 验证配置、打包、控制器、shell 与 DNS 行为。

## 版本发布

运行工件附有 `SHA256SUMS.txt` 和 `build-info.json`，记录包哈希、构建提交、规则输入及双核心校验值。

## 许可证

规则和运行核心的上游许可见[第三方来源](../docs/THIRD-PARTY.md)。

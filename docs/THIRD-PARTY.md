# 第三方规则和组件

以下参考点在 2026-11-27 核对。规则生成器按 [来源清单](../routing/routing-sources.json) 读取上游地址，每次 Actions 构建在 `build-info.json` 记录实际输入的 URL 和 SHA-256。

| 来源 | 输入和已知参考点 | 上游条款 |
| --- | --- | --- |
| [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) | `rule` 的 `adblockdns.txt`，`main` 参考提交 `0438d33cb566f8cff724d771f663989f0c94dd30` | [GPL v3](https://github.com/217heidai/adblockfilters/blob/0438d33cb566f8cff724d771f663989f0c94dd30/LICENSE) |
| [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | GeoSite 和 GeoIP，核对的发布为 [202611262204](https://github.com/Loyalsoldier/v2ray-rules-dat/releases/tag/202611262204)，`master` 参考提交 `9a1fbf47e0a1f673eac87ebe90178db5ecd7d21c` | [GPL v3](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/9a1fbf47e0a1f673eac87ebe90178db5ecd7d21c/LICENSE) |
| [Aethersailor/Custom_OpenClash_Rules](https://github.com/Aethersailor/Custom_OpenClash_Rules) | 直连、代理、Steam CDN MRS 和端口 YAML，`main` 参考提交 `29c3712753c799b3a6c7b4cbcdb51c262bc9717a` | [CC BY-SA 4.0](https://github.com/Aethersailor/Custom_OpenClash_Rules/blob/29c3712753c799b3a6c7b4cbcdb51c262bc9717a/LICENCE) |
| [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) | `accelerated-domains.china.conf`，`master` 参考提交 `a30697b2725cbe2691312e12878ab3fea5697513` | [WTFPL v2，Copyright © 2013 Felix Yan](https://github.com/felixonmars/dnsmasq-china-list/blob/a30697b2725cbe2691312e12878ab3fea5697513/LICENSE) |
| [苍狼山庄 ISP IP](https://ispip.clang.cn/) | `all_cn.txt` 和 `all_cn_apnic.txt`，上游按 IPNetDB 和 APNIC 数据生成 | 来源页面未标明数据许可证 |

项目对规则做格式转换、规范化、按优先级裁剪并合并为 SRS 或 OpenWrt 策略。

- [自有 sing-box ARM64 0.0.2](https://github.com/lyleee0083/xiaomi-be7000-singbox/releases/tag/sing-box-xiaomi-be7000-0.0.2)，发布提交 `273a764394fb3db315b009d18f19c8046ee4ad76`，来自 [sing-box v1.14.4 源码及许可证](https://github.com/SagerNet/sing-box/tree/v1.14.4)。客户端 CI 用该核心编译与校验规则。
- [自有 MosDNS ARM64 0.0.2](https://github.com/lyleee0083/xiaomi-be7000-mosdns/releases/tag/mosdns-xiaomi-be7000-0.0.2)，发布提交 `5317ba126ac48419187f72bdc2d37409c0936c3f`。BE7000 CI 用该核心编译 MDRS 和校验配置。上游为 [mosdns v5 源码及许可证](https://github.com/IrineSistiana/mosdns/tree/9cfb7ce985599c087cb7ccfb1531d0c0f4021242)。

- [Zstandard 源码及许可证](https://github.com/meta/zstd)，Actions 通过 Ubuntu 的 libzstd1 解码 MRS。

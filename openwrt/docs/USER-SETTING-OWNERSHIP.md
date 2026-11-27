# 用户设置与项目归属

## 当前边界

本分支使用 OpenWrt fw4/nftables、mosdns 5.3.4 和项目固定 sing-box 1.14.4。本文说明本地方案的所有权边界，不代替设备运行验收；历史记录只适用于对应日期和版本。

| 用户控制，默认只读 | 仅项目集成明确授权后可修改 |
|---|---|
| dnsmasq 的并发、缓存、DHCP、LAN DNS 重定向及其他参数；WAN/LAN/Wi-Fi；固件；系统 DNS/路由/网卡；CPU/内核调优；ECM 开关和调试值 | 本项目自己的 sing-box/mosdns 配置与服务；nftables 表 `sb_proxy`、保留 mark 位和策略路由表；OpenWrt TUN 转发 ACCEPT UCI include `firewall.sb_proxy_forward` 与内部 TCP INPUT include `firewall.sb_proxy_input`；另行管理的项目专属 dnsmasq `server`／`noresolv` 选项 |

用户仍控制 dnsmasq，并将其作为主要 LAN DNS 服务。本方案不强制劫持 LAN TCP/UDP 53，不设置 dnsmasq 并发、缓存、DHCP 或全局 DNS 重定向。项目激活时如需增加专属 `server`／`noresolv` 接入，必须先保存准确原值，只改项目拥有选项；关闭、启动失败或核心异常退出时，只恢复这些选项。若现场值变化或归属冲突，停止并报告，不整份回放 DHCP/firewall。

ECM 开关和模块状态始终由用户控制。项目不写 ECM 开关，不轮询 ECM 作为健康门槛，不要求关闭硬件加速，也不以 ECM 计数判定分流成功。单独授权的旧加速缓存清理不等于修改 ECM 开关或全局 conntrack。

可选连接 verdict cache 只使用项目已有的 `0x60000000` connmark 保留位，不扩展标记位、不清除 conntrack，也不写 ECM/PPE/SFE/flow-offload 设置。GitHub Actions 构建使用 `ctmark-v1`。缓存的设备行为与性能需在目标路由器验收。

sing-box 仅负责代理，不启用 `auto_redirect`；项目 nftables 只操作登记的自有规则/集合及保留标记位。启动失败或进程退出时，按事件路径清理项目对象并恢复项目选项；不持续监控、自动修复用户环境或自动重启核心。已实现本地生命周期模型，真实设备行为仍待单独验证。核心首条拒绝 IPv6、mosdns 拒绝 AAAA；项目不添加 IPv6 策略路由或禁用固件全局 IPv6。

生成、打包、核心资产准备、部署、激活、服务重启、固件升级、用户网络变更和验收彼此独立。核心资产准备函数只使用固定版本与摘要，将官方 ARM64 和 Windows 校验文件缓存到 `openwrt/build-stage/cores/`；不刷新规则，也不更新 `D:\Software\sing-box`。

项目状态目录为 `/etc/sing-box-state/`。

历史报告、诊断证据、备份和恢复快照均保留，不进入运行包。历史验收不能证明当前设备行为；未完成的实现不得表述为已部署或已验收。

# NNRRWrt Userspace & LuCI Packages (`nnrrwrt-packages`)

Userspace daemon, CLI utility, and LuCI web application feed for [NNRRWrt](https://github.com/grislux55/nnrrwrt), covering optical PON line management, dual-stack isolated TR-069 CWMP sandboxing, real-time gateway telemetry, IPTV bridge isolation, and read-only UBI calibration/identity backup.

[NNRRWrt](https://github.com/grislux55/nnrrwrt) 的用户态守护进程、命令行工具与 LuCI 应用软件包源，涵盖 PON 光路与协议栈管理、双栈隔离 TR-069 CWMP 沙盒、网关实时总览仪表盘、IPTV 专口桥接隔离以及关键 UBI 分区只读备份（PON 基础组件基于上游 [pbs05/openwrt-pon-userspace](https://github.com/pbs05/openwrt-pon-userspace) 演进扩展）。

## Package Matrix / 软件包一览

### 1. Gateway Overview UI / 网关总览界面

| Package / 软件包 | Version / 版本 | Directory / 目录 | Purpose / 职责说明 |
| --- | --- | --- | --- |
| `luci-app-nnrrwrt-dashboard` | 0.1.0 | `luci-app-nnrrwrt-dashboard/` | Real-time optical gateway dashboard (`admin/dashboard`): physical port & 10-LED panel, dual optical power & WAN/LAN traffic scopes, PPE hardware offload & thermal/system telemetry / 实时光猫网关总览仪表盘（端口与 10 颗 LED 面板、双光强与流量示波器、PPE 硬件卸载与温控指标） |

### 2. PON Control, Protocol Agent & Board Backup / PON 控制、协议代理与板级备份

| Package / 软件包 | Version / 版本 | Directory / 目录 | Purpose / 职责说明 |
| --- | --- | --- | --- |
| `airoha-pond` | 0.3.0 | `airoha-pon-daemons/` | Rust OMCI & IEEE 802.3ah OAM protocol agent, including dual-stack TR-069 management channel discovery (`ME 134/136/340/347`) / Rust OMCI 与 OAM 协议守护进程（含双栈管理通道 `ME 134/136/340/347` 解析导出） |
| `airoha-ponctl` | 0.2.0 | `airoha-ponctl/` | Rust PON line configuration, optical diagnostics, and Netlink control CLI (`ponctl`) / PON 线路配置、光模块诊断与状态工具 |
| `airoha-pon-debug` | 0.1.0 | `airoha-pon-debug/` | Diagnostic bundle & packet capture collector / PON 状态快照与报文抓包诊断工具 |
| `luci-app-pon` | 0.1.0 | `luci-app-pon/` | LuCI PON configuration, board identity editor, read-only 5-volume UBI backup (`bosa`/`ri`/`fip`/`ubootenv`/`ubootenv2`), and `pon0-*` LED trigger plugins / PON 配置、身份编辑、五卷 UBI 只读备份与 `pon0-*` LED 触发器插件 |

### 3. Isolated Management Sandbox / 隔离管理通道沙盒

| Package / 软件包 | Version / 版本 | Directory / 目录 | Purpose / 职责说明 |
| --- | --- | --- | --- |
| `airoha-tr069-fake` | 0.1.0 | `airoha-tr069-fake/` | Dual-stack isolated TR-069 (CWMP) Rust sandbox client with persistent virtual TR-098/TR-181 model, dedicated `netifd`/`fw4` routing table, and sanitized `/tmp` audit ring log / 双栈隔离 TR-069 CWMP 虚拟模型沙盒守护进程 |
| `luci-app-tr069-fake` | 0.1.0 | `luci-app-tr069-fake/` | LuCI configuration, virtual parameter diff viewer, and sanitized audit log inspector for `airoha-tr069-fake` / TR-069 Fake 沙盒配置、虚拟参数覆盖与脱敏日志界面 |

### 4. IPTV & Bridge Isolation / IPTV 专口桥接

| Package / 软件包 | Version / 版本 | Directory / 目录 | Purpose / 职责说明 |
| --- | --- | --- | --- |
| `luci-app-iptv` | 0.1.0 | `luci-app-iptv/` | Dedicated `br-iptv` port bridge and `nftables` bridge forward isolation / IPTV 独立网桥与 `nftables` 桥接转发隔离配置应用 |

## OpenWrt Feed Integration / Feed 接入方式

```text
src-git nnrrwrt_packages https://github.com/grislux55/nnrrwrt-packages.git
```

## Local Verification / 本地校验

```sh
cargo test --manifest-path airoha-pon-daemons/src/Cargo.toml --offline --locked
cargo test --manifest-path airoha-ponctl/src/Cargo.toml --offline --locked
cargo test --manifest-path airoha-tr069-fake/src/Cargo.toml --offline --locked
```

## Documentation & Attribution / 文档与致谢

- Board identity & Nokia `ri` layout specification: [IDENTITY.md](IDENTITY.md)
- Upstream PON userspace foundation: [pbs05/openwrt-pon-userspace](https://github.com/pbs05/openwrt-pon-userspace)

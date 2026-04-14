# ICMP ISAV Prober

支持两类 ICMP 探测（Unreachable / Fragmentation）并支持隧道封装：

- `ipip`
- `gre`
- `ip6ip6`
- `gre6`
- `4in6`
- `6to4`

## Python 版本（功能完整）

### 6to4 专用实现说明

针对 `6to4`，Python 代码按如下三层结构构造探测包：

1. 外层：`IP(src=Scanner_V4, dst=Target_V4, proto=41)`
2. 内层：`IPv6(src=Spoofed_V6_in_2002_target_prefix, dst=Target_6to4_V6)`
3. 载荷：`ICMPv6DestUnreach` 或 `ICMPv6PacketTooBig` + 触发原始包头

并在 `scan --ip-version 4 --tunnel 6to4` 时对 IPv4 网段（可设置为全网）执行该逻辑。

```bash
python3 icmp_isav_probe.py scan \
  --ip-version 4 \
  --ipv4-cidr 0.0.0.0/0 \
  --methods both \
  --tunnel 6to4 \
  --scanner-v4 1.1.1.1 \
  --scanner-v6 2001:db8::1 \
  --output-csv not_deployed_isav_6to4.csv
```

> 注意：当 `--tunnel 6to4` 时，Python 代码会强制按 `0.0.0.0/0` 全网 IPv4 扫描。

## C 版本（高速发包）

新增 `fast_6to4_sender.c`：

- 目标：快速发送 6to4 `ICMPv6 Packet Too Big` 探测包。
- 默认速率：`10000` pps（可通过参数调整）。
- 输入：IPv4 目标列表文件（每行一个 IPv4）。
- 发包结构：
  - Outer IPv4 (proto 41)
  - Inner IPv6 (spoofed src in target 6to4 /48)
  - ICMPv6 PTB + quoted IPv6/UDP trigger

### 编译

```bash
gcc -O3 -std=c11 -Wall -Wextra -o fast_6to4_sender fast_6to4_sender.c
```

### 运行（10000 pps）

```bash
sudo ./fast_6to4_sender 1.1.1.1 2001:db8::1 targets_v4.txt 10000 c_sent_v4.csv
```

### 全网 IPv4（6to4）高速扫描

```bash
sudo ./fast_6to4_sender 1.1.1.1 2001:db8::1 --full-v4 10000 c_sent_v4.csv
```

参数含义：

1. `scanner_v4`：扫描器外层 IPv4
2. `scanner_v6`：扫描器内层 IPv6
3. `targets_v4.txt`：目标 IPv4 列表
4. `pps`：每秒发包速率（默认 10000）
5. `output_csv`：C 发包结果输出（默认 `c_sent_v4.csv`，保存 `target_v4,status`）

## 输出

Python 扫描最终输出 CSV 仅包含一列：`target_v4`。  
仅写入判定为 `packet_not_intercepted` 的 IPv4 地址（用于无状态入站源地址验证 ISAV 部署结果汇总）。

C 发包器也会保存输出 CSV（`target_v4,status`），记录成功发送的 IPv4 目标。

## 依赖

- Python 3.9+
- Scapy（Python 版本需要）
- GCC（C 版本编译）

## 注意

- 所有原始发包操作都需要 root 权限。
- `0.0.0.0/0` 扫描规模极大，建议先小网段验证。

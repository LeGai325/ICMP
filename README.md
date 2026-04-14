# ICMP ISAV Prober

支持两类 ICMP 探测（Unreachable / Fragmentation）并支持隧道封装：

- `ipip`
- `gre`
- `ip6ip6`
- `gre6`
- `4in6`
- `6to4`

## 6to4 专用实现说明

针对 `6to4`，代码已按如下三层结构构造探测包：

1. 外层：`IP(src=Scanner_V4, dst=Target_V4, proto=41)`
2. 内层：`IPv6(src=Spoofed_V6_in_2002_target_prefix, dst=Target_6to4_V6)`
3. 载荷：`ICMPv6DestUnreach` 或 `ICMPv6PacketTooBig` + 触发原始包头

并在 `scan --ip-version 4 --tunnel 6to4` 时对 IPv4 网段（可设置为全网）执行该逻辑。

## 核心命令

### 1) 6to4 全网 IPv4 扫描（按需改小网段）

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

### 2) 其他隧道 IPv4 扫描

```bash
python3 icmp_isav_probe.py scan --ip-version 4 --ipv4-cidr 198.51.100.0/24 --methods both --tunnel gre --output-csv not_deployed_isav_v4.csv
```

### 3) IPv6 数据集扫描（csv/txt）

```bash
python3 icmp_isav_probe.py scan --ip-version 6 --targets-file ipv6_targets.csv --tunnel gre6 --output-csv not_deployed_isav_v6.csv
```

## 参数说明

- `--ip-version {4,6}`：选择 IPv4 或 IPv6 扫描。
- `--ipv4-cidr`：IPv4 扫描网段，默认 `0.0.0.0/0`。
- `--targets-file`：IPv6 目标文件（CSV/TXT）。
- `--methods {both,unreach,frag}`：探测方法组合。
- `--port`：Unreachable 方法端口，默认 `80`。
- `--tunnel`：`ipip|gre|ip6ip6|gre6|4in6|6to4`。
- `--scanner-v4`：仅 `6to4` 模式需要，扫描器外层 IPv4。
- `--scanner-v6`：仅 `6to4` 模式需要，扫描器内层 IPv6。
- `--output-csv`：输出 CSV。
- `--iface`：可选网卡。

## 输出

输出 CSV 列为：`target, method, status`，仅写入 `packet_not_intercepted`。

## 依赖

- Python 3.9+
- Scapy

```bash
pip install scapy
```

## 注意

- 扫描通常需要 root/raw socket 权限。
- `0.0.0.0/0` 扫描规模极大，建议先小网段验证。

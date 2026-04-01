# ICMP ISAV Prober

支持两类 ICMP 探测（Unreachable / Fragmentation）并新增**隧道协议封装扫描**：

- `ipip`
- `gre`
- `ip6ip6`
- `gre6`
- `4in6`
- `6to4`

并支持：

- **IPv4**：按网段批量扫描（默认 `0.0.0.0/0`，即全网）。
- **IPv6**：从你提供的 `csv/txt` 数据集读取目标（每行一个地址；CSV 时取首列）。
- 最终输出疑似**未部署 ISAV** 地址到 CSV。

## 核心命令

```bash
python3 icmp_isav_probe.py scan --ip-version 4 --ipv4-cidr 0.0.0.0/0 --methods both --tunnel gre --output-csv not_deployed_isav_v4.csv

python3 icmp_isav_probe.py scan --ip-version 6 --targets-file ipv6_targets.csv --tunnel gre6 --output-csv not_deployed_isav_v6.csv
```

## 参数说明

- `--ip-version {4,6}`：选择 IPv4 或 IPv6 扫描。
- `--ipv4-cidr`：IPv4 扫描网段，默认全网 `0.0.0.0/0`。
- `--targets-file`：IPv6 目标文件（CSV/TXT）。
- `--methods {both,unreach,frag}`：IPv4 下探测方法组合。
- `--port`：Unreachable 方法目标端口，默认 `80`。
- `--tunnel`：隧道协议 `ipip|gre|ip6ip6|gre6|4in6|6to4`。
- `--output-csv`：输出“未部署 ISAV”结果文件。
- `--iface`：可选网卡。

## 输出格式

输出 CSV 列：

- `target`
- `method`
- `status`

仅输出 `status = packet_not_intercepted` 的地址。

## 依赖

- Python 3.9+
- Scapy

```bash
pip install scapy
```

## 说明

- 运行扫描通常需要 root/raw socket 权限。
- 全网 IPv4 扫描规模极大，建议先用较小 CIDR 验证。

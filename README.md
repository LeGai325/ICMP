# ICMP ISAV Prober

按论文流程实现两类互补探测（Unreachable / Fragmentation），并支持隧道封装：

- `ipip`
- `gre`
- `ip6ip6`
- `gre6`
- `4in6`
- `6to4`

## Python 版本（功能完整）

## 核心流程（已实现）

### 阶段 1：可测目标筛选（Measurable Targets）

#### Unreachable 方法

对每个 IPv4 目标先做基准与中断测试，满足 `n1 - n2 >= 2` 才进入伪造探测：

1. 基准测试：发送 TCP SYN，统计 SYN/ACK 重传数 `n1`
2. 中断测试：收到首个 SYN/ACK 后，发送真实源 IP 的 ICMP Unreachable，统计重传数 `n2`
3. 判定：`n1 - n2 >= 2` 则该主机（端口）可测

默认自动在 `22/53/80/443` 中筛选可测端口；可用 `--port` 指定单端口。

#### Fragmentation 方法（IPv4）

1. 基准测试：发送 1300 字节 Ping，要求回复不分片
2. 降级测试：发送真实源 IP 的 ICMP Fragment Needed（MTU=1300）
3. 再次发送 1300 字节 Ping，若回复分片则可测

### 阶段 2：伪造探测（Spoofed Probing）

通过阶段 1 后，使用目标相邻 IP（neighbor IP）作为伪造源发包：

- Unreachable：发送伪造源 ICMP Unreachable（引用触发的 TCP 连接头）
- Fragmentation：发送伪造源 ICMP Fragment Needed 后再测大包 Ping

### 阶段 3：结果判定

- `packet_not_intercepted`：疑似未部署 ISAV
- `packet_intercepted`：疑似已部署 ISAV
- `inconclusive`：不满足可测条件或响应不足

### 6to4 专用实现说明

针对 `6to4`，Python 代码按如下三层结构构造探测包：

1. 外层：`IP(src=Scanner_V4, dst=Target_V4, proto=41)`
2. 内层：`IPv6(src=Spoofed_V6_in_2002_target_prefix, dst=Target_6to4_V6)`
3. 载荷：`ICMPv6DestUnreach` 或 `ICMPv6PacketTooBig` + 触发原始包头

并在 `scan --ip-version 4 --tunnel 6to4` 时对 IPv4 网段执行该逻辑。

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

## 扫描命令

### IPv4 全网扫描（普通 IPv4）

```bash
sudo python3 icmp_isav_probe.py scan \
  --ip-version 4 \
  --ipv4-cidr 0.0.0.0/0 \
  --methods both \
  --output-csv isav_ipv4_results.csv
```

### IPv6 扫描（从文件读取，每行一个 IPv6）

```bash
sudo python3 icmp_isav_probe.py scan \
  --ip-version 6 \
  --targets-file ipv6_targets.txt \
  --methods frag \
  --output-csv isav_ipv6_results.csv
```

`ipv6_targets.txt` 示例：

```text
2001:db8::1
2400:3200::1234
2a00:1450:4009:81b::200e
```

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

Python 扫描输出 CSV 字段：

- `target`
- `method`
- `status`
- `note`

即每个目标都会输出结果（包括 `inconclusive`），便于后处理筛选。

C 发包器也会保存输出 CSV（`target_v4,status`），记录成功发送的 IPv4 目标。

## 依赖

- Python 3.9+
- Scapy（Python 版本需要）
- GCC（C 版本编译）

## 注意

- 所有原始发包操作都需要 root 权限。
- `0.0.0.0/0` 扫描规模极大，建议先小网段验证。

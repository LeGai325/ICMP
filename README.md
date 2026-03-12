# ICMP ISAV Prober

该仓库实现了论文中的两种互补探测逻辑：

1. **ICMP Unreachable 方法**：利用伪造 ICMP 不可达报文观察 TCP 重传是否中断。
2. **ICMP Fragmentation 方法**：利用伪造 ICMP Fragment Needed 报文观察目标是否按伪造 PMTU 触发分片回复。

主程序：`icmp_isav_probe.py`

## 功能对应关系

### 阶段 1：可测目标筛选

- `measure-unreach`
  - 对目标端口执行两轮 SYN/SYN-ACK 重传测量，得到 `n1`（基准）与 `n2`（中断）。
  - 判定规则：`n1 - n2 >= 2` => 可测。

- `measure-frag`
  - 先发 1300-byte payload ping 观察基准是否分片；
  - 再发 ICMP Fragment Needed 后重测；
  - 判定规则：第一次不分片、第二次分片 => 可测。

### 阶段 2：ISAV 伪造探测

- `probe-unreach`
  - 发送 SYN；
  - 收到 SYN/ACK 后发送伪造源地址（默认目标邻居 IP）的 ICMP Unreachable；
  - 比较重传数量变化。

- `probe-frag`
  - 发送伪造源地址（默认目标邻居 IP）的 ICMP Fragment Needed（MTU=1300）；
  - 之后发送 1300-byte payload ping；
  - 观察 Echo Reply 是否分片。

### 阶段 3：结果判定

- `packet_not_intercepted`：伪造包穿透（疑似未部署 ISAV）。
- `packet_intercepted`：伪造包被拦截（疑似已部署 ISAV）。
- `inconclusive`：无应答或证据不足。

## 运行示例

> 需要 root 权限和可发送原始报文的网络环境。

```bash
python3 icmp_isav_probe.py measure-unreach 203.0.113.10 --ports 22,80,443
python3 icmp_isav_probe.py measure-frag 203.0.113.10
python3 icmp_isav_probe.py probe-unreach 203.0.113.10 --port 80
python3 icmp_isav_probe.py probe-frag 203.0.113.10
```

## 依赖

- Python 3.9+
- Scapy

```bash
pip install scapy
```

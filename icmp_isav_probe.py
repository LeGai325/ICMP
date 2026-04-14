#!/usr/bin/env python3
"""ISAV probing implementation with tunnel-packet support.

Special support for 6to4 (IPv4 Protocol 41 carrying IPv6):
- Outer IPv4: scanner_v4 -> target_v4, proto=41
- Inner IPv6: spoofed source inside target's 2002:V4HEX:V4HEX::/48 -> target 6to4 address
- Payload: ICMPv6 Destination Unreachable or Packet Too Big
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import random
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from scapy.all import (
    GRE,
    ICMP,
    ICMPv6DestUnreach,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6PacketTooBig,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    conf,
    send,
    sniff,
    sr1,
)


class IsavStatus(str, Enum):
    NOT_INTERCEPTED = "packet_not_intercepted"
    INTERCEPTED = "packet_intercepted"
    INCONCLUSIVE = "inconclusive"


class TunnelProtocol(str, Enum):
    IPIP = "ipip"
    GRE = "gre"
    IP6IP6 = "ip6ip6"
    GRE6 = "gre6"
    V4IN6 = "4in6"
    SIX_TO_FOUR = "6to4"


@dataclass
class ProbeDecision:
    target: str
    method: str
    status: IsavStatus
    note: str = ""


class TunnelPacketBuilder:
    @staticmethod
    def wrap(inner_pkt, tunnel: TunnelProtocol, src: str, dst: str):
        if tunnel == TunnelProtocol.IPIP:
            return IP(src=src, dst=dst, proto=4) / inner_pkt
        if tunnel == TunnelProtocol.GRE:
            return IP(src=src, dst=dst) / GRE() / inner_pkt
        if tunnel == TunnelProtocol.IP6IP6:
            return IPv6(src=src, dst=dst, nh=41) / inner_pkt
        if tunnel == TunnelProtocol.GRE6:
            return IPv6(src=src, dst=dst) / GRE() / inner_pkt
        if tunnel == TunnelProtocol.V4IN6:
            return IPv6(src=src, dst=dst, nh=4) / inner_pkt
        if tunnel == TunnelProtocol.SIX_TO_FOUR:
            return IP(src=src, dst=dst, proto=41) / inner_pkt
        raise ValueError(f"unsupported tunnel protocol: {tunnel}")


class IsavProber:
    def __init__(self, iface: Optional[str] = None):
        if iface:
            conf.iface = iface

    @staticmethod
    def neighbor_ip(target: str) -> str:
        obj = ipaddress.ip_address(target)
        if int(obj) == 0:
            raise ValueError("cannot compute neighbor for address zero")
        return str(obj - 1)

    @staticmethod
    def six_to_four_prefix(target_v4: str) -> ipaddress.IPv6Network:
        v4 = ipaddress.IPv4Address(target_v4)
        h = f"{int(v4):08x}"
        p1, p2 = h[:4], h[4:]
        return ipaddress.IPv6Network(f"2002:{p1}:{p2}::/48")

    @classmethod
    def six_to_four_target_ipv6(cls, target_v4: str) -> str:
        return str(cls.six_to_four_prefix(target_v4).network_address + 1)

    @classmethod
    def six_to_four_spoofed_ipv6(cls, target_v4: str) -> str:
        prefix = cls.six_to_four_prefix(target_v4)
        # choose random host in /48 but avoid :: and ::1
        rid = random.randint(0x1000, 0xFFFFFFFF)
        return str(prefix.network_address + rid)

    def _count_synack_retransmissions(
        self,
        target: str,
        port: int,
        timeout_s: float,
        interrupt_with_icmp_unreach: bool,
        interrupt_src_ip: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> int:
        sport = 40000 + int(time.time() * 1000) % 20000
        syn = IP(dst=target) / TCP(sport=sport, dport=port, flags="S", seq=1000)
        synack = sr1(syn, timeout=2, verbose=False)
        if not synack or not synack.haslayer(TCP):
            return 0

        if interrupt_with_icmp_unreach:
            scanner_ip = conf.route.route(target)[1]
            outer_src = interrupt_src_ip if interrupt_src_ip else scanner_ip
            inner = IP(src=target, dst=scanner_ip) / TCP(
                sport=port,
                dport=sport,
                flags="SA",
                seq=synack[TCP].seq,
                ack=synack[TCP].ack,
            )
            crafted = IP(src=outer_src, dst=target) / ICMP(type=3, code=1) / bytes(inner)[:28]
            if tunnel is not None and tunnel != TunnelProtocol.SIX_TO_FOUR:
                crafted = TunnelPacketBuilder.wrap(crafted, tunnel=tunnel, src=outer_src, dst=target)
            send(crafted, verbose=False)

        bpf = (
            f"tcp and src host {target} and src port {port} "
            f"and dst port {sport} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"
        )
        packets = sniff(filter=bpf, timeout=timeout_s)
        return len(packets)

    def find_measurable_unreachable_port(self, target: str, ports: Sequence[int]) -> Tuple[Optional[int], Dict[int, Tuple[int, int]]]:
        """阶段1：筛选对 ICMP Unreachable 有 RFC 兼容反应的目标端口。"""
        details: Dict[int, Tuple[int, int]] = {}
        scanner_ip = conf.route.route(target)[1]
        for port in ports:
            n1 = self._count_synack_retransmissions(target, port, 8, False)
            n2 = self._count_synack_retransmissions(target, port, 8, True, scanner_ip, None)
            details[port] = (n1, n2)
            if (n1 - n2) >= 2:
                return port, details
        return None, details

    def probe_unreachable_ipv4(
        self,
        target: str,
        port: int = 80,
        spoofed_source: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> ProbeDecision:
        source = spoofed_source or self.neighbor_ip(target)
        baseline = self._count_synack_retransmissions(target, port, 8, False)
        spoofed = self._count_synack_retransmissions(target, port, 8, True, source, tunnel)
        status = IsavStatus.NOT_INTERCEPTED if (baseline - spoofed) >= 2 else IsavStatus.INTERCEPTED
        return ProbeDecision(target=target, method="unreachable", status=status, note=f"port={port},n1={baseline},n2={spoofed}")

    def _send_frag_needed_ipv4(self, target: str, source: str, tunnel: Optional[TunnelProtocol], mtu: int = 1300) -> None:
        scanner_ip = conf.route.route(target)[1]
        inner = IP(src=target, dst=scanner_ip) / ICMP(type=8, code=0) / Raw(b"A" * 8)
        pkt = IP(src=source, dst=target) / ICMP(type=3, code=4, unused=mtu) / bytes(inner)[:28]
        if tunnel is not None and tunnel != TunnelProtocol.SIX_TO_FOUR:
            pkt = TunnelPacketBuilder.wrap(pkt, tunnel=tunnel, src=source, dst=target)
        send(pkt, verbose=False)

    def is_measurable_fragment_ipv4(self, target: str) -> bool:
        """阶段1：筛选能被 Fragment Needed 报文影响 PMTU 的目标。"""
        baseline = sr1(IP(dst=target) / ICMP(type=8, code=0) / Raw(b"B" * 1300), timeout=3, verbose=False)
        if baseline is None or baseline.flags.MF == 1 or baseline.frag > 0:
            return False
        scanner_ip = conf.route.route(target)[1]
        self._send_frag_needed_ipv4(target=target, source=scanner_ip, tunnel=None, mtu=1300)
        time.sleep(2)
        second = sr1(IP(dst=target) / ICMP(type=8, code=0) / Raw(b"B" * 1300), timeout=3, verbose=False)
        if second is None:
            return False
        return second.flags.MF == 1 or second.frag > 0

    def probe_fragment_ipv4(
        self,
        target: str,
        spoofed_source: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> ProbeDecision:
        source = spoofed_source or self.neighbor_ip(target)
        self._send_frag_needed_ipv4(target=target, source=source, tunnel=tunnel, mtu=1300)
        time.sleep(2)
        req = IP(dst=target) / ICMP(type=8, code=0) / Raw(b"B" * 1300)
        rep = sr1(req, timeout=3, verbose=False)
        if rep is None:
            status = IsavStatus.INCONCLUSIVE
        elif rep.flags.MF == 1 or rep.frag > 0:
            status = IsavStatus.NOT_INTERCEPTED
        else:
            status = IsavStatus.INTERCEPTED
        return ProbeDecision(target=target, method="fragment", status=status)

    def probe_fragment_ipv6(
        self,
        target: str,
        spoofed_source: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> ProbeDecision:
        source = spoofed_source or self.neighbor_ip(target)
        scanner_ip = conf.route6.route(target)[1]
        inner = IPv6(src=target, dst=scanner_ip) / ICMPv6EchoRequest(data=b"A" * 8)
        pkt = IPv6(src=source, dst=target) / ICMPv6PacketTooBig(mtu=1300) / bytes(inner)[:48]
        if tunnel is not None and tunnel != TunnelProtocol.SIX_TO_FOUR:
            pkt = TunnelPacketBuilder.wrap(pkt, tunnel=tunnel, src=source, dst=target)
        send(pkt, verbose=False)
        time.sleep(2)
        req = IPv6(dst=target) / ICMPv6EchoRequest(data=b"B" * 1300)
        rep = sr1(req, timeout=3, verbose=False)
        if rep is None:
            status = IsavStatus.INCONCLUSIVE
        elif rep.haslayer("IPv6ExtHdrFragment"):
            status = IsavStatus.NOT_INTERCEPTED
        else:
            status = IsavStatus.INTERCEPTED
        return ProbeDecision(target=target, method="fragment6", status=status)

    # -------- 6to4 专用实现 (outer IPv4 + inner IPv6 + ICMPv6 payload) --------
    def _send_6to4_icmpv6_unreach(
        self,
        scanner_v4: str,
        scanner_v6: str,
        target_v4: str,
        target_v6: str,
        spoofed_v6: str,
        sport: int,
        dport: int,
        seq: int,
        ack: int,
    ) -> None:
        trigger_pkt = IPv6(src=target_v6, dst=scanner_v6) / TCP(
            sport=dport,
            dport=sport,
            flags="SA",
            seq=seq,
            ack=ack,
        )
        inner = IPv6(src=spoofed_v6, dst=target_v6) / ICMPv6DestUnreach(code=1) / trigger_pkt
        pkt = IP(src=scanner_v4, dst=target_v4, proto=41) / inner
        send(pkt, verbose=False)

    def _send_6to4_icmpv6_ptb(
        self,
        scanner_v4: str,
        scanner_v6: str,
        target_v4: str,
        target_v6: str,
        spoofed_v6: str,
        mtu: int = 1280,
    ) -> None:
        trigger_pkt = IPv6(src=target_v6, dst=scanner_v6) / UDP(sport=53, dport=12345)
        inner = IPv6(src=spoofed_v6, dst=target_v6) / ICMPv6PacketTooBig(mtu=mtu) / trigger_pkt
        pkt = IP(src=scanner_v4, dst=target_v4, proto=41) / inner
        send(pkt, verbose=False)

    def _send_6to4_echo_request(self, scanner_v4: str, scanner_v6: str, target_v4: str, target_v6: str, size: int):
        inner = IPv6(src=scanner_v6, dst=target_v6) / ICMPv6EchoRequest(data=b"B" * size)
        pkt = IP(src=scanner_v4, dst=target_v4, proto=41) / inner
        return sr1(pkt, timeout=3, verbose=False)

    def probe_6to4_fragment(
        self,
        target_v4: str,
        scanner_v4: str,
        scanner_v6: str,
    ) -> ProbeDecision:
        target_v6 = self.six_to_four_target_ipv6(target_v4)
        spoofed_v6 = self.six_to_four_spoofed_ipv6(target_v4)

        baseline = self._send_6to4_echo_request(scanner_v4, scanner_v6, target_v4, target_v6, size=1300)
        baseline_frag = baseline is not None and baseline.haslayer("IPv6ExtHdrFragment")

        self._send_6to4_icmpv6_ptb(scanner_v4, scanner_v6, target_v4, target_v6, spoofed_v6, mtu=1280)
        time.sleep(2)
        rep2 = self._send_6to4_echo_request(scanner_v4, scanner_v6, target_v4, target_v6, size=1300)

        if rep2 is None:
            status = IsavStatus.INCONCLUSIVE
        else:
            downgraded_frag = rep2.haslayer("IPv6ExtHdrFragment")
            status = IsavStatus.NOT_INTERCEPTED if (not baseline_frag and downgraded_frag) else IsavStatus.INTERCEPTED

        return ProbeDecision(target=target_v4, method="6to4-fragment", status=status)

    def probe_6to4_unreachable(
        self,
        target_v4: str,
        scanner_v4: str,
        scanner_v6: str,
        dport: int = 80,
    ) -> ProbeDecision:
        target_v6 = self.six_to_four_target_ipv6(target_v4)
        spoofed_v6 = self.six_to_four_spoofed_ipv6(target_v4)
        sport = 40000 + int(time.time() * 1000) % 20000

        syn = IP(src=scanner_v4, dst=target_v4, proto=41) / IPv6(src=scanner_v6, dst=target_v6) / TCP(
            sport=sport,
            dport=dport,
            flags="S",
            seq=1000,
        )
        first = sr1(syn, timeout=3, verbose=False)
        if first is None or not first.haslayer(TCP):
            return ProbeDecision(target=target_v4, method="6to4-unreachable", status=IsavStatus.INCONCLUSIVE)

        bpf = f"ip proto 41 and src host {target_v4} and dst host {scanner_v4}"

        baseline_pkts = sniff(filter=bpf, timeout=8)
        baseline = sum(1 for p in baseline_pkts if p.haslayer(TCP) and p[TCP].flags & 0x12 == 0x12)

        self._send_6to4_icmpv6_unreach(
            scanner_v4=scanner_v4,
            scanner_v6=scanner_v6,
            target_v4=target_v4,
            target_v6=target_v6,
            spoofed_v6=spoofed_v6,
            sport=sport,
            dport=dport,
            seq=first[TCP].seq,
            ack=first[TCP].ack,
        )
        spoofed_pkts = sniff(filter=bpf, timeout=8)
        spoofed = sum(1 for p in spoofed_pkts if p.haslayer(TCP) and p[TCP].flags & 0x12 == 0x12)

        status = IsavStatus.NOT_INTERCEPTED if (baseline - spoofed) >= 2 else IsavStatus.INTERCEPTED
        return ProbeDecision(target=target_v4, method="6to4-unreachable", status=status)


def load_ipv6_targets(file_path: str) -> List[str]:
    targets: List[str] = []
    with Path(file_path).open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            ip = ipaddress.ip_address(line)
            if ip.version == 6:
                targets.append(line)
    return targets


def iter_ipv4_targets(cidr: str) -> Iterator[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    for ip in net:
        if ip.version == 4:
            yield str(ip)


def write_results_csv(rows: Sequence[ProbeDecision], out_csv: str) -> None:
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "method", "status", "note"])
        for row in rows:
            writer.writerow([row.target, row.method, row.status.value, row.note])


def run_scan(args: argparse.Namespace) -> None:
    prober = IsavProber(iface=args.iface)
    tunnel = TunnelProtocol(args.tunnel) if args.tunnel else None
    decisions: List[ProbeDecision] = []

    if args.ip_version == 4:
        scan_cidr = args.ipv4_cidr
        if tunnel == TunnelProtocol.SIX_TO_FOUR:
            scan_cidr = "0.0.0.0/0"
            print("[info] 6to4 模式固定扫描全网 IPv4: 0.0.0.0/0")
        for target in iter_ipv4_targets(scan_cidr):
            if tunnel == TunnelProtocol.SIX_TO_FOUR:
                if not args.scanner_v4 or not args.scanner_v6:
                    raise ValueError("6to4 扫描需要 --scanner-v4 和 --scanner-v6")
                if args.methods in ("both", "frag"):
                    r = prober.probe_6to4_fragment(target, scanner_v4=args.scanner_v4, scanner_v6=args.scanner_v6)
                    decisions.append(r)
                    print(f"[6to4-frag] {target} -> {r.status.value}")
                if args.methods in ("both", "unreach"):
                    r = prober.probe_6to4_unreachable(target, scanner_v4=args.scanner_v4, scanner_v6=args.scanner_v6, dport=args.port)
                    decisions.append(r)
                    print(f"[6to4-unreach] {target} -> {r.status.value}")
            else:
                if args.methods in ("both", "frag"):
                    if prober.is_measurable_fragment_ipv4(target):
                        r = prober.probe_fragment_ipv4(target=target, tunnel=tunnel)
                    else:
                        r = ProbeDecision(target=target, method="fragment", status=IsavStatus.INCONCLUSIVE, note="not measurable")
                    decisions.append(r)
                    print(f"[v4-frag] {target} -> {r.status.value} {r.note}")
                if args.methods in ("both", "unreach"):
                    selected_port, details = prober.find_measurable_unreachable_port(target, [22, 53, 80, 443] if args.port <= 0 else [args.port])
                    if selected_port is None:
                        r = ProbeDecision(target=target, method="unreachable", status=IsavStatus.INCONCLUSIVE, note=f"not measurable:{details}")
                    else:
                        r = prober.probe_unreachable_ipv4(target=target, port=selected_port, tunnel=tunnel)
                    decisions.append(r)
                    print(f"[v4-unreach] {target} -> {r.status.value} {r.note}")
    else:
        if not args.targets_file:
            raise ValueError("IPv6 扫描必须提供 --targets-file (每行一个 IPv6 地址)")
        for target in load_ipv6_targets(args.targets_file):
            r = prober.probe_fragment_ipv6(target=target, tunnel=tunnel)
            decisions.append(r)
            print(f"[v6-frag] {target} -> {r.status.value}")

    write_results_csv(decisions, args.output_csv)
    print(f"已输出扫描结果到: {args.output_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ISAV ICMP probing tool with tunnel support")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="批量扫描并导出未部署ISAV地址CSV")
    scan.add_argument("--ip-version", type=int, choices=[4, 6], required=True)
    scan.add_argument("--ipv4-cidr", default="0.0.0.0/0", help="IPv4扫描网段（6to4模式下将被强制为0.0.0.0/0）")
    scan.add_argument("--targets-file", help="IPv6目标CSV/TXT文件，每行一个地址（可带逗号附加列）")
    scan.add_argument("--methods", choices=["both", "unreach", "frag"], default="both")
    scan.add_argument("--port", type=int, default=-1, help="Unreachable探测端口，默认-1表示自动在22/53/80/443中筛选可测端口")
    scan.add_argument(
        "--tunnel",
        choices=[t.value for t in TunnelProtocol],
        help="隧道协议: ipip, gre, ip6ip6, gre6, 4in6, 6to4",
    )
    scan.add_argument("--scanner-v4", help="6to4模式下扫描器外层IPv4")
    scan.add_argument("--scanner-v6", help="6to4模式下扫描器内层IPv6")
    scan.add_argument("--output-csv", default="not_deployed_isav.csv")
    scan.add_argument("--iface", default=None)

    args = parser.parse_args()
    if args.cmd == "scan":
        run_scan(args)


if __name__ == "__main__":
    main()

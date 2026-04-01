#!/usr/bin/env python3
"""ISAV probing implementation with tunnel-packet support.

Features:
- ICMP Unreachable and ICMP Fragmentation probing logic (IPv4)
- ICMPv6 Packet Too Big based fragmentation probing (IPv6)
- Tunnel encapsulation options: ipip, gre, ip6ip6, gre6, 4in6, 6to4
- IPv4 global scan mode (0.0.0.0/0 by default, configurable)
- IPv6 dataset scan mode (CSV/TXT, one address per line)
- CSV output of addresses inferred as "not deployed ISAV"
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

from scapy.all import GRE, ICMP, ICMPv6EchoRequest, ICMPv6PacketTooBig, IP, IPv6, Raw, TCP, conf, send, sr1, sniff


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


class TunnelPacketBuilder:
    """Wrap an inner packet with a selected tunnel protocol."""

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
            if tunnel is not None:
                crafted = TunnelPacketBuilder.wrap(crafted, tunnel=tunnel, src=outer_src, dst=target)
            send(crafted, verbose=False)

        bpf = (
            f"tcp and src host {target} and src port {port} "
            f"and dst port {sport} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"
        )
        packets = sniff(filter=bpf, timeout=timeout_s)
        return len(packets)

    def probe_unreachable_ipv4(
        self,
        target: str,
        port: int = 80,
        spoofed_source: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> ProbeDecision:
        source = spoofed_source or self.neighbor_ip(target)
        baseline = self._count_synack_retransmissions(
            target=target,
            port=port,
            timeout_s=8,
            interrupt_with_icmp_unreach=False,
            tunnel=tunnel,
        )
        spoofed = self._count_synack_retransmissions(
            target=target,
            port=port,
            timeout_s=8,
            interrupt_with_icmp_unreach=True,
            interrupt_src_ip=source,
            tunnel=tunnel,
        )
        status = IsavStatus.NOT_INTERCEPTED if (baseline - spoofed) >= 2 else IsavStatus.INTERCEPTED
        return ProbeDecision(target=target, method="unreachable", status=status)

    def _send_fragment_needed_ipv4(
        self,
        target: str,
        spoofed_source: str,
        mtu: int,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> None:
        scanner_ip = conf.route.route(target)[1]
        inner = IP(src=target, dst=scanner_ip) / ICMP(type=8, code=0) / Raw(b"A" * 8)
        pkt = IP(src=spoofed_source, dst=target) / ICMP(type=3, code=4, unused=mtu) / bytes(inner)[:28]
        if tunnel is not None:
            pkt = TunnelPacketBuilder.wrap(pkt, tunnel=tunnel, src=spoofed_source, dst=target)
        send(pkt, verbose=False)

    def _send_packet_too_big_ipv6(
        self,
        target: str,
        spoofed_source: str,
        mtu: int,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> None:
        scanner_ip = conf.route6.route(target)[1]
        inner = IPv6(src=target, dst=scanner_ip) / ICMPv6EchoRequest(data=b"A" * 8)
        pkt = IPv6(src=spoofed_source, dst=target) / ICMPv6PacketTooBig(mtu=mtu) / bytes(inner)[:48]
        if tunnel is not None:
            pkt = TunnelPacketBuilder.wrap(pkt, tunnel=tunnel, src=spoofed_source, dst=target)
        send(pkt, verbose=False)

    @staticmethod
    def _is_fragmented_ipv4(rep) -> Optional[bool]:
        if rep is None:
            return None
        return rep.flags.MF == 1 or rep.frag > 0

    @staticmethod
    def _is_fragmented_ipv6(rep) -> Optional[bool]:
        if rep is None:
            return None
        return rep.haslayer("IPv6ExtHdrFragment")

    def probe_fragment_ipv4(
        self,
        target: str,
        spoofed_source: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> ProbeDecision:
        source = spoofed_source or self.neighbor_ip(target)
        self._send_fragment_needed_ipv4(target=target, spoofed_source=source, mtu=1300, tunnel=tunnel)
        time.sleep(2)
        req = IP(dst=target) / ICMP(type=8, code=0) / Raw(b"B" * 1300)
        rep = sr1(req, timeout=3, verbose=False)
        frag = self._is_fragmented_ipv4(rep)
        if frag is True:
            status = IsavStatus.NOT_INTERCEPTED
        elif frag is False:
            status = IsavStatus.INTERCEPTED
        else:
            status = IsavStatus.INCONCLUSIVE
        return ProbeDecision(target=target, method="fragment", status=status)

    def probe_fragment_ipv6(
        self,
        target: str,
        spoofed_source: Optional[str] = None,
        tunnel: Optional[TunnelProtocol] = None,
    ) -> ProbeDecision:
        source = spoofed_source or self.neighbor_ip(target)
        self._send_packet_too_big_ipv6(target=target, spoofed_source=source, mtu=1300, tunnel=tunnel)
        time.sleep(2)
        req = IPv6(dst=target) / ICMPv6EchoRequest(data=b"B" * 1300)
        rep = sr1(req, timeout=3, verbose=False)
        frag = self._is_fragmented_ipv6(rep)
        if frag is True:
            status = IsavStatus.NOT_INTERCEPTED
        elif frag is False:
            status = IsavStatus.INTERCEPTED
        else:
            status = IsavStatus.INCONCLUSIVE
        return ProbeDecision(target=target, method="fragment6", status=status)


def load_ipv6_targets(file_path: str) -> List[str]:
    targets: List[str] = []
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            first = line.split(",")[0].strip()
            ip = ipaddress.ip_address(first)
            if ip.version == 6:
                targets.append(first)
    return targets


def iter_ipv4_targets(cidr: str) -> Iterator[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    for ip in net:
        if ip.version == 4:
            yield str(ip)


def write_not_intercepted_csv(rows: Sequence[ProbeDecision], out_csv: str) -> None:
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["target", "method", "status"])
        for row in rows:
            if row.status == IsavStatus.NOT_INTERCEPTED:
                writer.writerow([row.target, row.method, row.status.value])


def run_scan(args: argparse.Namespace) -> None:
    prober = IsavProber(iface=args.iface)
    tunnel = TunnelProtocol(args.tunnel) if args.tunnel else None
    positives: List[ProbeDecision] = []

    if args.ip_version == 4:
        for target in iter_ipv4_targets(args.ipv4_cidr):
            if args.methods in ("both", "unreach"):
                res = prober.probe_unreachable_ipv4(target=target, port=args.port, tunnel=tunnel)
                print(f"[v4-unreach] {target} -> {res.status.value}")
                positives.append(res)
            if args.methods in ("both", "frag"):
                res = prober.probe_fragment_ipv4(target=target, tunnel=tunnel)
                print(f"[v4-frag] {target} -> {res.status.value}")
                positives.append(res)
    else:
        if not args.targets_file:
            raise ValueError("IPv6 扫描必须提供 --targets-file (csv/txt)")
        for target in load_ipv6_targets(args.targets_file):
            res = prober.probe_fragment_ipv6(target=target, tunnel=tunnel)
            print(f"[v6-frag] {target} -> {res.status.value}")
            positives.append(res)

    write_not_intercepted_csv(positives, args.output_csv)
    print(f"已输出疑似未部署ISAV地址到: {args.output_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ISAV ICMP probing tool with tunnel support")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="批量扫描并导出未部署ISAV地址CSV")
    scan.add_argument("--ip-version", type=int, choices=[4, 6], required=True)
    scan.add_argument("--ipv4-cidr", default="0.0.0.0/0", help="IPv4扫描网段，默认全网")
    scan.add_argument("--targets-file", help="IPv6目标CSV/TXT文件，每行一个地址（可带逗号附加列）")
    scan.add_argument("--methods", choices=["both", "unreach", "frag"], default="both")
    scan.add_argument("--port", type=int, default=80, help="Unreachable方法使用的TCP目标端口")
    scan.add_argument(
        "--tunnel",
        choices=[t.value for t in TunnelProtocol],
        help="隧道协议: ipip, gre, ip6ip6, gre6, 4in6, 6to4",
    )
    scan.add_argument("--output-csv", default="not_deployed_isav.csv")
    scan.add_argument("--iface", default=None)

    args = parser.parse_args()
    if args.cmd == "scan":
        run_scan(args)


if __name__ == "__main__":
    main()

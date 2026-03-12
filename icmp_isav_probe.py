#!/usr/bin/env python3
"""ISAV probing implementation for ICMP Unreachable and Fragmentation methods.

This module follows the methodology described in the paper/workflow:
1) measurable target filtering
2) spoofed probing
3) result judgement
"""

from __future__ import annotations

import argparse
import ipaddress
import time
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional, Tuple

from scapy.all import ICMP, IP, TCP, Raw, conf, send, sr1, sniff


class IsavStatus(str, Enum):
    NOT_INTERCEPTED = "packet_not_intercepted"
    INTERCEPTED = "packet_intercepted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class UnreachableMeasurableResult:
    target: str
    port: int
    baseline_retransmissions: int
    interrupted_retransmissions: int

    @property
    def measurable(self) -> bool:
        return (self.baseline_retransmissions - self.interrupted_retransmissions) >= 2


@dataclass
class FragmentMeasurableResult:
    target: str
    baseline_fragmented: bool
    downgraded_fragmented: bool

    @property
    def measurable(self) -> bool:
        return (not self.baseline_fragmented) and self.downgraded_fragmented


@dataclass
class UnreachableProbeResult:
    target: str
    port: int
    spoofed_source: str
    baseline_retransmissions: int
    spoofed_retransmissions: int

    @property
    def status(self) -> IsavStatus:
        if (self.baseline_retransmissions - self.spoofed_retransmissions) >= 2:
            return IsavStatus.NOT_INTERCEPTED
        return IsavStatus.INTERCEPTED


@dataclass
class FragmentProbeResult:
    target: str
    spoofed_source: str
    reply_fragmented: Optional[bool]

    @property
    def status(self) -> IsavStatus:
        if self.reply_fragmented is True:
            return IsavStatus.NOT_INTERCEPTED
        if self.reply_fragmented is False:
            return IsavStatus.INTERCEPTED
        return IsavStatus.INCONCLUSIVE


class IsavProber:
    def __init__(self, iface: Optional[str] = None):
        if iface:
            conf.iface = iface

    @staticmethod
    def neighbor_ip(target: str) -> str:
        ip_obj = ipaddress.ip_address(target)
        if int(ip_obj) == 0:
            raise ValueError("cannot compute neighbor for zero address")
        return str(ip_obj - 1)

    def _count_synack_retransmissions(
        self,
        target: str,
        port: int,
        timeout_s: float,
        interrupt_with_icmp_unreach: bool,
        interrupt_src_ip: Optional[str] = None,
    ) -> int:
        sport = 40000 + int(time.time() * 1000) % 20000
        syn = IP(dst=target) / TCP(sport=sport, dport=port, flags="S", seq=1000)
        synack = sr1(syn, timeout=2, verbose=False)
        if not synack or not synack.haslayer(TCP):
            return 0

        if interrupt_with_icmp_unreach:
            outer_src = interrupt_src_ip if interrupt_src_ip else conf.route.route(target)[1]
            inner = IP(src=target, dst=conf.route.route(target)[1]) / TCP(
                sport=port,
                dport=sport,
                flags="SA",
                seq=synack[TCP].seq,
                ack=synack[TCP].ack,
            )
            icmp_unreach = IP(src=outer_src, dst=target) / ICMP(type=3, code=1) / bytes(inner)[:28]
            send(icmp_unreach, verbose=False)

        bpf = (
            f"tcp and src host {target} and src port {port} "
            f"and dst port {sport} and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0"
        )
        packets = sniff(filter=bpf, timeout=timeout_s)
        return len(packets)

    def measure_unreachable_targets(
        self,
        targets: Iterable[str],
        ports: Iterable[int] = (22, 53, 80, 443),
        timeout_s: float = 8.0,
    ) -> List[UnreachableMeasurableResult]:
        results: List[UnreachableMeasurableResult] = []
        for target in targets:
            for port in ports:
                n1 = self._count_synack_retransmissions(
                    target=target,
                    port=port,
                    timeout_s=timeout_s,
                    interrupt_with_icmp_unreach=False,
                )
                n2 = self._count_synack_retransmissions(
                    target=target,
                    port=port,
                    timeout_s=timeout_s,
                    interrupt_with_icmp_unreach=True,
                )
                results.append(
                    UnreachableMeasurableResult(
                        target=target,
                        port=port,
                        baseline_retransmissions=n1,
                        interrupted_retransmissions=n2,
                    )
                )
        return results

    def _send_fragment_needed(self, target: str, spoofed_source: str, mtu: int) -> None:
        scanner_ip = conf.route.route(target)[1]
        inner = IP(src=target, dst=scanner_ip) / ICMP(type=8, code=0) / Raw(b"A" * 8)
        frag_needed = (
            IP(src=spoofed_source, dst=target)
            / ICMP(type=3, code=4, unused=mtu)
            / bytes(inner)[:28]
        )
        send(frag_needed, verbose=False)

    def _ping_fragmented_reply(self, target: str, payload_size: int) -> Optional[bool]:
        req = IP(dst=target) / ICMP(type=8, code=0) / Raw(b"B" * payload_size)
        rep = sr1(req, timeout=3, verbose=False)
        if rep is None:
            return None
        return rep.flags.MF == 1 or rep.frag > 0

    def measure_fragment_targets(
        self,
        targets: Iterable[str],
        payload_size: int = 1300,
        mtu: int = 1300,
    ) -> List[FragmentMeasurableResult]:
        results: List[FragmentMeasurableResult] = []
        for target in targets:
            baseline = self._ping_fragmented_reply(target, payload_size=payload_size)
            spoofed = conf.route.route(target)[1]
            self._send_fragment_needed(target, spoofed_source=spoofed, mtu=mtu)
            time.sleep(2)
            downgraded = self._ping_fragmented_reply(target, payload_size=payload_size)
            results.append(
                FragmentMeasurableResult(
                    target=target,
                    baseline_fragmented=bool(baseline),
                    downgraded_fragmented=bool(downgraded),
                )
            )
        return results

    def probe_unreachable(self, target: str, port: int, spoofed_source: Optional[str] = None) -> UnreachableProbeResult:
        source = spoofed_source or self.neighbor_ip(target)
        baseline = self._count_synack_retransmissions(
            target=target,
            port=port,
            timeout_s=8,
            interrupt_with_icmp_unreach=False,
        )
        spoofed = self._count_synack_retransmissions(
            target=target,
            port=port,
            timeout_s=8,
            interrupt_with_icmp_unreach=True,
            interrupt_src_ip=source,
        )
        return UnreachableProbeResult(
            target=target,
            port=port,
            spoofed_source=source,
            baseline_retransmissions=baseline,
            spoofed_retransmissions=spoofed,
        )

    def probe_fragment(self, target: str, spoofed_source: Optional[str] = None) -> FragmentProbeResult:
        source = spoofed_source or self.neighbor_ip(target)
        self._send_fragment_needed(target=target, spoofed_source=source, mtu=1300)
        time.sleep(2)
        fragmented = self._ping_fragmented_reply(target, payload_size=1300)
        return FragmentProbeResult(
            target=target,
            spoofed_source=source,
            reply_fragmented=fragmented,
        )


def _parse_ports(ports: str) -> Tuple[int, ...]:
    return tuple(int(p.strip()) for p in ports.split(",") if p.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description="ISAV ICMP probing tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    m1 = sub.add_parser("measure-unreach")
    m1.add_argument("targets", nargs="+")
    m1.add_argument("--ports", default="22,53,80,443")

    m2 = sub.add_parser("measure-frag")
    m2.add_argument("targets", nargs="+")

    p1 = sub.add_parser("probe-unreach")
    p1.add_argument("target")
    p1.add_argument("--port", type=int, default=80)
    p1.add_argument("--spoofed-source")

    p2 = sub.add_parser("probe-frag")
    p2.add_argument("target")
    p2.add_argument("--spoofed-source")

    args = parser.parse_args()
    prober = IsavProber()

    if args.cmd == "measure-unreach":
        results = prober.measure_unreachable_targets(args.targets, ports=_parse_ports(args.ports))
        for item in results:
            print(
                f"{item.target}:{item.port} n1={item.baseline_retransmissions} "
                f"n2={item.interrupted_retransmissions} measurable={item.measurable}"
            )
    elif args.cmd == "measure-frag":
        results = prober.measure_fragment_targets(args.targets)
        for item in results:
            print(
                f"{item.target} baseline_fragmented={item.baseline_fragmented} "
                f"downgraded_fragmented={item.downgraded_fragmented} measurable={item.measurable}"
            )
    elif args.cmd == "probe-unreach":
        res = prober.probe_unreachable(args.target, port=args.port, spoofed_source=args.spoofed_source)
        print(
            f"{res.target}:{res.port} baseline={res.baseline_retransmissions} "
            f"spoofed={res.spoofed_retransmissions} status={res.status.value}"
        )
    else:
        res = prober.probe_fragment(args.target, spoofed_source=args.spoofed_source)
        print(f"{res.target} reply_fragmented={res.reply_fragmented} status={res.status.value}")


if __name__ == "__main__":
    main()

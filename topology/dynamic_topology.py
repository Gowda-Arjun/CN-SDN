#!/usr/bin/env python3
"""Mininet topology for dynamic host-blocking demo."""

import argparse

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo


class DynamicBlockingTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")

        hosts = [
            ("h1", "10.0.0.1/24", "00:00:00:00:00:01"),
            ("h2", "10.0.0.2/24", "00:00:00:00:00:02"),
            ("h3", "10.0.0.3/24", "00:00:00:00:00:03"),
            ("h4", "10.0.0.4/24", "00:00:00:00:00:04"),
        ]

        for name, ip_addr, mac in hosts:
            host = self.addHost(name, ip=ip_addr, mac=mac)
            self.addLink(host, s1, cls=TCLink, bw=100, delay="2ms")


def run_topology(controller_ip, controller_port):
    topo = DynamicBlockingTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoStaticArp=True,
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    net.start()

    info("\n*** Network is up\n")
    info("*** Connected hosts:\n")
    for host in net.hosts:
        info(f"- {host.name}: {host.IP()} ({host.MAC()})\n")

    info("\n*** Suggested validation scenarios\n")
    info("1) Allowed traffic:\n")
    info("   mininet> h1 ping -c 3 h2\n")
    info("2) Suspicious traffic from attacker host h4:\n")
    info("   mininet> h4 ping -f -c 300 h2\n")
    info("3) Verify post-block behavior:\n")
    info("   mininet> h4 ping -c 3 h2\n")

    CLI(net)
    net.stop()


def parse_args():
    parser = argparse.ArgumentParser(description="Dynamic host-blocking Mininet topology")
    parser.add_argument("--controller-ip", default="127.0.0.1", help="Ryu controller IP")
    parser.add_argument("--controller-port", type=int, default=6653, help="Ryu controller port")
    return parser.parse_args()


def main():
    args = parse_args()
    run_topology(args.controller_ip, args.controller_port)


if __name__ == "__main__":
    setLogLevel("info")
    main()


# Enables: mn --custom topology/dynamic_topology.py --topo dynamicblockingtopo
topos = {"dynamicblockingtopo": DynamicBlockingTopo}

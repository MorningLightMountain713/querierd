#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright© 2023 by David White.
# Copyright© 2016 by Alexander Roessler.
# Based on the work of Mark Culler and others.
# This file is part of QuerierD.
#
# QuerierD is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# QuerierD is distributed in the hope that it will be useful
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with QuerierD.  If not, see <http://www.gnu.org/licenses/>.

from . import Querier
from typing import List, Optional
import threading
import time
import sys
import argparse
import os
import ipaddress
import netifaces


class QuerierInstance:
    def __init__(self, address: str, interval: int) -> None:
        self.address = address
        self.interval = interval
        self.querier = Querier(address, interval)
        self.thread = thread = threading.Thread(target=self.run)
        thread.start()

    def run(self) -> None:
        self.querier.run()

    def stop(self) -> None:
        self.querier.stop.set()


def private_addresses_for_interface(interface: str) -> List[str]:
    ips = []
    addresses = netifaces.ifaddresses(interface)

    if not netifaces.AF_INET in addresses:
        return ips

    for link in addresses[netifaces.AF_INET]:
        if ipaddress.ip_address(link["addr"]).is_private:
            ips.append(link["addr"])

    return ips


def ip4_addresses(
    all_interfaces: bool = False, interface: Optional[str] = None
) -> List[str]:

    if all_interfaces:
        ifaces = netifaces.interfaces()
        addresses = [
            addy
            for iface in ifaces
            for addy in private_addresses_for_interface(iface)
            if not iface == "lo"
        ]
    elif interface:
        addresses = private_addresses_for_interface(interface)
    else:  # use gateway
        gws = netifaces.gateways()
        try:
            upstream_inteface = gws["default"][netifaces.AF_INET][1]
        except ValueError:
            addresses = []
        else:
            addresses = private_addresses_for_interface(upstream_inteface)

    return addresses


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Querierd queries the multicast group in a certain interval to"
            " prevent IGMP snooping"
        )
    )
    parser.add_argument(
        "-i", "--interval", help="IGMP query interval", default=60.0
    )
    parser.add_argument(
        "-f", "--interface", help="IGMP query interface", default=None
    )
    parser.add_argument(
        "-a",
        "--all-interfaces",
        help="Run on all interfaces, instead of default route",
        action="store_true",
    )
    parser.add_argument(
        "-d", "--debug", help="Enable debug mode", action="store_true"
    )
    parser.add_argument(
        "-v", "--version", help="IGMP Version (1 or 2)", default=2
    )
    args = parser.parse_args()

    if os.getuid() != 0:
        print("You must be root to run a querier.")
        sys.exit(1)

    debug = args.debug
    interval = args.interval
    interface = args.interface
    all_interfaces = args.interface
    version = args.version
    wait = 5.0  # network interface checking interval
    processes = {}

    try:
        while True:
            addresses = ip4_addresses(all_interfaces, interface)
            for address in addresses:
                if address not in processes:
                    if debug:
                        print("adding new querier: %s" % address)
                    processes[address] = QuerierInstance(
                        address, interval, version
                    )

            removed = []
            for proc in processes:
                if proc not in addresses:
                    if debug:
                        print("stopping querier: %s" % proc)
                    processes[proc].stop()
                    removed.append(proc)
            for proc in removed:
                processes.pop(proc)

            time.sleep(wait)
    except KeyboardInterrupt:
        pass

    if debug:
        print("stopping threads")
    for proc in processes:
        processes[proc].stop()

    # wait for all threads to terminate
    while threading.active_count() > 1:  # one thread for every process is left
        time.sleep(0.1)

    if debug:
        print("threads stopped")
    sys.exit(0)


if __name__ == "__main__":
    main()

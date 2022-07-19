"""
Utils for network sniffing
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Any

from netaddr import IPAddress
from scapy.interfaces import NetworkInterface
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP
from scapy.packet import Packet
from scapy.sendrecv import sniff

from utils.network.network_utils import get_local_ip

__author__: str = "Michael Weichenrieder"


class NetworkSniffer(Thread):
    """
    Sniffs incoming network traffic for network devices
    """

    def __init__(self, network_interface: NetworkInterface, sniff_arp: bool = True, sniff_icmp_echo: bool = True,
                 sniff_icmp_timestamp: bool = True, sniff_ip_packets: bool = True):
        """
        Create a new network and start it

        :param network_interface: The network interface to use
        :param sniff_arp: If arp responses should be sniffed
        :param sniff_icmp_echo: If icmp echo responses should be sniffed
        :param sniff_icmp_timestamp:If icmp timestamp responses should be sniffed
        :param sniff_ip_packets: If all packets with ip header should be sniffed
        """
        super().__init__()
        self.sniff_arp: bool = sniff_arp
        self.sniff_icmp_echo: bool = sniff_icmp_echo
        self.sniff_icmp_timestamp: bool = sniff_icmp_timestamp
        self.sniff_ip_packets: bool = sniff_ip_packets
        self.network_interface: NetworkInterface = network_interface
        self.local_ip: str = get_local_ip(network_interface)
        self.discovered_devices: {str, str} = {}

        # Exit when main thread exits
        super().setDaemon(True)
        self.start()

    def save_discovered_device(self, ip: str, mac: str) -> None:
        """
        Saves a discovered device

        :param ip: Ip address of the discovered device
        :param mac: Mac address of the discovered device
        """
        # Mac 00:00:00:00:00:00 is used for loopback packets to current machine
        if mac != "00:00:00:00:00:00" and ip != self.local_ip:
            # Save discovered devices if not already in list or mac changed
            if ip not in self.discovered_devices.keys() or self.discovered_devices[ip] != mac:
                self.discovered_devices[ip] = mac

    def handle_sniffed_packet(self, sniffed: Packet) -> None:
        """
        Handle a sniffed packet

        :param sniffed: The sniffed packet
        """
        # Filter for packet types
        if self.sniff_arp and ARP in sniffed and sniffed[ARP].op == 2:
            # Filter for is-at (id 2) ARP packets
            self.save_discovered_device(sniffed[ARP].psrc, sniffed.src)
        elif self.sniff_icmp_echo and ICMP in sniffed and sniffed[ICMP].type == 0:
            # Filter for echo-reply (id 0) ICMP packets
            self.save_discovered_device(sniffed[IP].src, sniffed.src)
        elif self.sniff_icmp_timestamp and ICMP in sniffed and sniffed[ICMP].type == 14:
            # Filter for timestamp-reply (id 14) ICMP packets
            self.save_discovered_device(sniffed[IP].src, sniffed.src)
        elif self.sniff_ip_packets and IP in sniffed:
            # Filter for other packets with ip header and private ips (passive network discovery)
            ip: str = sniffed[IP].src
            if IPAddress(ip).is_private():
                self.save_discovered_device(ip, sniffed.src)

    def get_discovered_devices(self) -> {str, str}:
        """
        Get the discovered devices

        :return: A map with ip keys and mac values
        """
        return self.discovered_devices

    def run(self) -> None:
        """
        Thread contents
        """
        # Don't store to keep RAM free
        sniff(prn=self.handle_sniffed_packet, iface=self.network_interface, store=0)


class HttpSniffer(Thread):
    """
    Sniffs incoming network traffic for https requests from target device
    """

    class HttpHandler(BaseHTTPRequestHandler):
        """
        Handles http requests
        """

        def log_message(self, format: str, *args: Any) -> None:
            """
            Overwrite logging to show messages to user
            TODO: Print via logger
            """
            if "curl" in str(self.headers).lower():
                print(f"Received CURL: {self.client_address[0]}")
            elif "wget" in str(self.headers).lower():
                print(f"Received WGET: {self.client_address[0]}")

    def __init__(self, port: int):
        """
        Create a http sniffer and start it

        :param port: The port to sniff on
        """
        super().__init__()
        self.port = port
        super().setDaemon(True)
        self.start()

    def run(self) -> None:
        """
        Thread contents
        """
        with HTTPServer(("", self.port), HttpSniffer.HttpHandler) as httpd:
            httpd.serve_forever()


class PingSniffer(Thread):
    """
    Sniffs incoming network traffic for pings from target device
    """

    def __init__(self, network_interface: NetworkInterface):
        """
        Create ping sniffer and start it

        :param network_interface: The interface to sniff on
        """
        super().__init__()
        self.network_interface: NetworkInterface = network_interface
        self.local_ip: str = get_local_ip(network_interface)
        super().setDaemon(True)
        self.start()

    @staticmethod
    def handle_sniffed_packet(sniffed: Packet) -> None:
        """
        Handle a sniffed packet
        TODO: Print via logger

        :param sniffed: The sniffed packet
        """
        # Filter for echo-request (id 8) ICMP packets (ping)
        if ICMP in sniffed and sniffed[ICMP].type == 8:
            print(f"Received PING: {sniffed.src} >> {sniffed[IP].src}")

    def run(self) -> None:
        """
        Thread contents
        """
        # Don't store to keep RAM free
        sniff(prn=PingSniffer.handle_sniffed_packet, filter="icmp", iface=self.network_interface, store=0)

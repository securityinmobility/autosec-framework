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

from autosec.core import UserInteraction
from autosec.core.ressources import InternetInterface, InternetDevice

__author__: str = "Michael Weichenrieder"


class NetworkSniffer(Thread):
    """
    Sniffs incoming network traffic for network devices
    """

    def __init__(self, internet_interface: InternetInterface, sniff_arp: bool = True, sniff_icmp_echo: bool = True,
                 sniff_icmp_timestamp: bool = True, sniff_ip_packets: bool = True):
        """
        Create a new network and start it

        :param internet_interface: The network interface to use
        :param sniff_arp: If arp responses should be sniffed
        :param sniff_icmp_echo: If icmp echo responses should be sniffed
        :param sniff_icmp_timestamp:If icmp timestamp responses should be sniffed
        :param sniff_ip_packets: If all packets with ip header should be sniffed
        """
        super().__init__()
        self._sniff_arp: bool = sniff_arp
        self._sniff_icmp_echo: bool = sniff_icmp_echo
        self._sniff_icmp_timestamp: bool = sniff_icmp_timestamp
        self._sniff_ip_packets: bool = sniff_ip_packets
        self._internet_interface = internet_interface
        self._discovered_devices: {str, str} = {}

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
        if mac != "00:00:00:00:00:00" and ip != self._internet_interface.get_ipv4_address():
            # Save discovered devices if not already in list or mac changed
            if ip not in self._discovered_devices.keys() or self._discovered_devices[ip] != mac:
                self._discovered_devices[ip] = mac

    def handle_sniffed_packet(self, sniffed: Packet) -> None:
        """
        Handle a sniffed packet

        :param sniffed: The sniffed packet
        """
        # Filter for packet types
        if self._sniff_arp and ARP in sniffed and sniffed[ARP].op == 2:
            # Filter for is-at (id 2) ARP packets
            self.save_discovered_device(sniffed[ARP].psrc, sniffed.src)
        elif self._sniff_icmp_echo and ICMP in sniffed and sniffed[ICMP].type == 0:
            # Filter for echo-reply (id 0) ICMP packets
            self.save_discovered_device(sniffed[IP].src, sniffed.src)
        elif self._sniff_icmp_timestamp and ICMP in sniffed and sniffed[ICMP].type == 14:
            # Filter for timestamp-reply (id 14) ICMP packets
            self.save_discovered_device(sniffed[IP].src, sniffed.src)
        elif self._sniff_ip_packets and IP in sniffed:
            # Filter for other packets with ip header and private ips (passive network discovery)
            ip: str = sniffed[IP].src
            if IPAddress(ip).is_private():
                self.save_discovered_device(ip, sniffed.src)

    def get_discovered_devices(self) -> [InternetDevice]:
        """
        Get the discovered devices

        :return: A map with ip keys and mac values
        """
        # Create list
        device_list: [InternetDevice] = []
        for ip, mac in self._discovered_devices.items():
            device_list.append(InternetDevice(
                interface=self._internet_interface,
                ipv4=ip,
                mac=mac
            ))

        # Return list
        return device_list

    def run(self) -> None:
        """
        Thread contents
        """
        # Don't store to keep RAM free
        sniff(prn=self.handle_sniffed_packet, iface=self._internet_interface.get_scapy_interface(), store=0)


class HttpSniffer(Thread):
    """
    Sniffs incoming network traffic for https requests from target device
    """

    user_interaction: UserInteraction = None

    class HttpHandler(BaseHTTPRequestHandler):
        """
        Handles http requests
        """

        def log_message(self, format: str, *args: Any) -> None:
            """
            Overwrite logging to show messages to user
            """
            if "curl" in str(self.headers).lower():
                HttpSniffer.user_interaction.feedback(f"Received CURL: {self.client_address[0]}")
            elif "wget" in str(self.headers).lower():
                HttpSniffer.user_interaction.feedback(f"Received WGET: {self.client_address[0]}")

    def __init__(self, port: int, user_interaction: UserInteraction):
        """
        Create a http sniffer and start it

        :param port: The port to sniff on
        :param user_interaction: User interaction for logging
        """
        super().__init__()
        self._port = port
        type(self).user_interaction = user_interaction
        super().setDaemon(True)
        self.start()

    def run(self) -> None:
        """
        Thread contents
        """
        with HTTPServer(("", self._port), HttpSniffer.HttpHandler) as httpd:
            httpd.serve_forever()


class PingSniffer(Thread):
    """
    Sniffs incoming network traffic for pings from target device
    """

    def __init__(self, internet_interface: InternetInterface, user_interaction: UserInteraction):
        """
        Create ping sniffer and start it

        :param internet_interface: The interface to sniff on
        :param user_interaction: User interaction for logging
        """
        super().__init__()
        self._network_interface: NetworkInterface = internet_interface.get_scapy_interface()
        self._user_interaction = user_interaction
        super().setDaemon(True)
        self.start()

    def handle_sniffed_packet(self, sniffed: Packet) -> None:
        """
        Handle a sniffed packet

        :param sniffed: The sniffed packet
        """
        # Filter for echo-request (id 8) ICMP packets (ping)
        if ICMP in sniffed and sniffed[ICMP].type == 8:
            self._user_interaction.feedback(f"Received PING: {sniffed.src} >> {sniffed[IP].src}")

    def run(self) -> None:
        """
        Thread contents
        """
        # Don't store to keep RAM free
        sniff(prn=self.handle_sniffed_packet, filter="icmp", iface=self._network_interface, store=0)

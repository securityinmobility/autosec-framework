"""
Network scanner module

Scapy documentation: https://scapy.readthedocs.io/en/latest/usage.html
Scan types: https://www.hackingarticles.in/nmap-for-pentester-ping-scan
"""
import logging
from time import sleep
from typing import Union, Type

from netaddr import IPNetwork
from scapy.interfaces import NetworkInterface
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp

from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation, AutosecExpectedMetrics
from autosec.core.ressources import InternetDevice, AutosecRessource, InternetInterface
from autosec.modules.infotainment_attacks.utils import ManufacturerMatcher
from utils.sniffer import NetworkSniffer

__author__: str = "Michael Weichenrieder"


class NetworkScanner(AutosecModule):
    """
    Network scanner module
    """

    # Parameters (estimated execution time: 38 minutes)
    _scan_arp: bool = True
    _scan_icmp_echo: bool = True
    _scan_icmp_timestamp: bool = True
    _scan_ip_packets: bool = True
    _chunk_size: int = 256
    _chunk_delay_seconds: float = 0
    _repetitions: int = 2

    def __init__(self):
        """
        Initialize logger in constructor
        """
        super().__init__()
        self._logger = logging.getLogger("autosec.modules.infotainment_attacks.network_scanner")
        self._logger.setLevel(logging.INFO)

    @classmethod
    def send_packets_arp(cls, network_interface: NetworkInterface, ips: [str]) -> None:
        """
        Send an arp packet for target identification
        Possible errors:
        - Response is not forwarded (https://stackallflow.com/superuser/wifi-range-extenders-and-failing-arp-requests/)
        - Request/response gets suppressed

        :param network_interface: The network interface to use
        :param ips: The ips to send the arp request to
        """
        packets_arp: [Ether] = []
        for ip in ips:
            packets_arp.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip))
        sendp(packets_arp, iface=network_interface, verbose=0)

    @classmethod
    def send_packets_icmp_echo(cls, network_interface: NetworkInterface, ips: [str]) -> None:
        """
        Send an icmp echo packet for target identification
        Possible errors:
        - Request/response gets suppressed

        :param network_interface: The network interface to use
        :param ips: The ips to send the icmp echo request to
        """
        packets_icmp: [Ether] = []
        for ip in ips:
            packets_icmp.append(Ether(dst="ff:ff:ff:ff:ff:ff") / (IP(dst=ip) / ICMP(type=8)))
        sendp(packets_icmp, iface=network_interface, verbose=0)

    @classmethod
    def send_packets_icmp_timestamp(cls, network_interface: NetworkInterface, ips: [str]) -> None:
        """
        Send an icmp timestamp packet for target identification
        Possible errors:
        - Request/response gets suppressed

        :param network_interface: The network interface to use
        :param ips: The ips to send the icmp timestamp request to
        """
        packets_icmp: [Ether] = []
        for ip in ips:
            packets_icmp.append(Ether(dst="ff:ff:ff:ff:ff:ff") / (IP(dst=ip) / ICMP(type=13)))
        sendp(packets_icmp, iface=network_interface, verbose=0)

    @classmethod
    def send_all_packets(cls, network_interface: NetworkInterface, ips: [str]) -> None:
        """
        Scan network via arp, icmp echo and icmp timestamp packets for best results
        Packets are selected according to object attributes

        :param network_interface: The network interface to use
        :param ips: The ips to send the requests to
        """
        if cls._scan_arp:
            cls.send_packets_arp(network_interface=network_interface, ips=ips)
        if cls._scan_icmp_echo:
            cls.send_packets_icmp_echo(network_interface=network_interface, ips=ips)
        if cls._scan_icmp_timestamp:
            cls.send_packets_icmp_timestamp(network_interface=network_interface, ips=ips)

    @classmethod
    def get_discovered_devices(cls, network_sniffer: NetworkSniffer) -> [InternetDevice]:
        """
        Get the discovered devices (sorted by ip) matched with manufacturer info

        :param network_sniffer: The network sniffer
        :return: A list of found internet devices
        """
        # Get devices and
        discovered_devices: [InternetDevice] = network_sniffer.get_discovered_devices()

        # Map manufacturers and return results
        return ManufacturerMatcher.update_manufacturers(discovered_devices)

    def get_info(self) -> AutosecModuleInformation:
        """
        :return: Basic info of the module
        """
        return AutosecModuleInformation(
            name=type(self).__name__,
            description="Scans the target network for devices",
            dependencies=["scapy", "netaddr"],
            tags=["network", "internet", "scan", "devices"]
        )

    def get_produced_outputs(self) -> [AutosecRessource]:
        """
        :return: Output resource examples
        """
        example_interface: InternetInterface = InternetInterface(
            interface="eth0",
            ipv4_address="192.168.90.125",
            subnet_length=16
        )
        return [
            InternetDevice(
                interface=example_interface,
                ipv4="192.168.20.2",
                mac="a4:34:d9:01:02:03",
                manufacturer="Intel Corporate"
            ),
            InternetDevice(
                interface=example_interface,
                ipv4="192.168.90.100",
                mac="a4:34:d9:01:02:03",
                manufacturer="Intel Corporate"
            )
        ]

    def get_required_ressources(self) -> [AutosecRessource]:
        """
        :return: Required input resource example
        """
        return [
            InternetInterface(
                interface="eth0",
                ipv4_address="192.168.90.125",
                subnet_length=16
            )
        ]

    def can_run(self, inputs: [AutosecRessource]) -> Union[bool, AutosecExpectedMetrics]:
        """
        :return: If the attack can run and metrics if it can
        """
        if super().can_run(inputs):
            internet_interface: InternetInterface = self.get_ressource(inputs, Type[InternetInterface])
            try:
                internet_interface.get_scapy_interface()
                chunk_count: int = (2 ** (32 - internet_interface.get_subnet_length())) / self._chunk_size
                seconds_per_chunk: float = 4.5  # Constant from tests
                return AutosecExpectedMetrics(
                    can_run=True,
                    expected_runtime=self._repetitions * chunk_count * (self._chunk_delay_seconds + seconds_per_chunk),
                    expected_success=.95  # Pretty unsure, not enough data
                )
            except Exception:
                # Scapy interface not present
                return False
        return False

    def run(self, inputs: [AutosecRessource]) -> [AutosecRessource]:
        """
        Run the attack

        :param inputs: The inputs (InternetInterface)
        :return: The results (InternetDevice)
        """
        # Get internet interface from input resources
        internet_interface: InternetInterface = self.get_ressource(inputs, Type[InternetInterface])

        # Create and start sniffer
        network_sniffer: NetworkSniffer = NetworkSniffer(internet_interface=internet_interface,
                                                         sniff_arp=self._scan_arp, sniff_icmp_echo=self._scan_icmp_echo,
                                                         sniff_icmp_timestamp=self._scan_icmp_timestamp,
                                                         sniff_ip_packets=self._scan_ip_packets)

        # Get network and init percentage calculation variables
        ips: [str] = [str(ip) for ip in IPNetwork(internet_interface.get_ipv4_address())]
        devices_found: int = 0

        # Go through repetitions
        for repetition in range(1, self._repetitions + 1):
            # Go through ips
            ips_left: [str] = ips.copy()
            while ips_left:
                # Pop next chunk
                chunk: [int] = ips_left[:self._chunk_size]
                ips_left = ips_left[self._chunk_size:]

                # Send packets in chunk
                # (is like sending one by one internally in library because response is not awaited)
                self.send_all_packets(internet_interface.get_scapy_interface(), chunk)

                # Check and log status
                current_device_count: int = len(network_sniffer.get_discovered_devices())
                while current_device_count > devices_found:
                    self._logger.warning("Network scanner found a device")

                # Pause
                sleep(self._chunk_delay_seconds)

        # Stop sniffer
        network_sniffer.stop()

        # Return results
        discovered_devices: [InternetDevice] = self.get_discovered_devices(network_sniffer)
        self._logger.info(f"Network scanner done. Network devices found: {len(discovered_devices)}")
        return discovered_devices

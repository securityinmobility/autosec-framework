"""
Port scanner module

TCP Syn-Scan: https://nmap.org/book/synscan.html
"""
import logging
import math
from typing import Union, Type

from scapy.interfaces import NetworkInterface
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import send, srp, sendp, sr

from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation, AutosecExpectedMetrics
from autosec.core.ressources import AutosecRessource, InternetInterface, InternetDevice, InternetService, PortRange

__author__: str = "Michael Weichenrieder"


class PortScanner(AutosecModule):
    """
    Port scanner module
    """

    # Parameters (estimated execution time: 9 minutes)
    _chunk_size: int = 500
    _chunk_delay_seconds: int = 1
    _max_repetitions: int = 2

    def __init__(self):
        """
        Initialize logger in constructor
        """
        super().__init__()
        self._logger = logging.getLogger("autosec.modules.infotainment_attacks.port_scanner")
        self._logger.setLevel(logging.INFO)

    def send_packets_tcp_syn(self, network_interface: NetworkInterface, target_ip: str, target_mac: Ether,
                             port_list: [int]) -> ([int], [int]):
        """
        Send a tcp syn packet for port check
        Possible errors:
        - Request/response gets suppressed (filtered port by firewall)

        :param network_interface: The network interface to use
        :param target_ip: Target ip for scan
        :param target_mac: Target mac for scan
        :param port_list List of ports to check
        :return Tuple: List of open ports and list of ports without response
        """
        # Init return lists
        ports_open: [int] = []
        ports_no_response: [int] = []

        # Bulk create, send and receive packets (if present, use mac for better results)
        if target_mac:
            packet_tcp_syn: Ether = target_mac / (IP(dst=target_ip) / TCP(dport=port_list, flags="S"))
            answered, unanswered = srp(packet_tcp_syn, iface=network_interface, timeout=self._chunk_delay_seconds,
                                       retry=0,
                                       verbose=0)
        else:
            packet_tcp_syn: IP = IP(dst=target_ip) / TCP(dport=port_list, flags="S")
            answered, unanswered = sr(packet_tcp_syn, iface=network_interface, timeout=self._chunk_delay_seconds,
                                      retry=0, verbose=0)

        # Check response packets
        for sent, received in answered:
            port: int = received[TCP].sport
            if received[TCP].flags == "SA":
                # Open port
                ports_open.append(port)

                # Close half-open connection
                if target_mac:
                    packet_tcp_ack: Ether = target_mac / (
                            IP(dst=target_ip) / TCP(sport=received[TCP].dport, dport=port, flags="R",
                                                    seq=received[TCP].ack, ack=received[TCP].seq + 1))
                    sendp(packet_tcp_ack, iface=network_interface, verbose=0)
                else:
                    packet_tcp_ack: IP = IP(dst=target_ip) / TCP(sport=received[TCP].dport, dport=port, flags="R",
                                                                 seq=received[TCP].ack, ack=received[TCP].seq + 1)
                    send(packet_tcp_ack, iface=network_interface, verbose=0)
            elif "R" in received[TCP].flags:
                # Closed port
                pass

        # Checked unanswered packets
        for sent in unanswered:
            # Filtered port or no response
            port: int = sent[TCP].dport
            ports_no_response.append(port)

        # Return results
        return ports_open, ports_no_response

    def get_info(self) -> AutosecModuleInformation:
        """
        :return: Basic info of the module
        """
        return AutosecModuleInformation(
            name=type(self).__name__,
            description="Scans the target device for open ports",
            dependencies=["scapy"],
            tags=["network", "internet", "scan", "port"]
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
        example_device: InternetDevice = InternetDevice(
            interface=example_interface,
            ipv4="192.168.90.100",
            mac="a4:34:d9:01:02:03",
            manufacturer="Intel Corporate"
        )
        return [
            InternetService(
                device=example_device,
                port=22
            ),
            InternetService(
                device=example_device,
                port=8080
            ),
            InternetService(
                device=example_device,
                port=8081
            )
        ]

    def get_required_ressources(self) -> [AutosecRessource]:
        """
        :return: Required input resource example
        """
        example_interface: InternetInterface = InternetInterface(
            interface="eth0",
            ipv4_address="192.168.90.125",
            subnet_length=16
        )
        return [
            InternetDevice(
                interface=example_interface,
                ipv4="192.168.90.100",
                mac="a4:34:d9:01:02:03",
                manufacturer="Intel Corporate"
            ),
            PortRange(
                start=1,
                end=65535
            )
        ]

    def can_run(self, inputs: [AutosecRessource]) -> Union[bool, AutosecExpectedMetrics]:
        """
        :return: If the attack can run and metrics if it can
        """
        if super().can_run(inputs):
            internet_device: InternetDevice = self.get_ressource(inputs, Type[InternetDevice])
            internet_interface: InternetInterface = internet_device.get_interface()
            port_range: PortRange = self.get_ressource(inputs, Type[PortRange])
            try:
                internet_device.get_ipv4()
                internet_device.get_mac()
                internet_interface.get_scapy_interface()
                chunk_count: int = math.ceil((port_range.get_end() - port_range.get_start() + 1) / self._chunk_size)
                seconds_per_chunk: float = 1.1  # Constant from tests
                return AutosecExpectedMetrics(
                    can_run=True,
                    # Highly depends on target firewall setup (expected is maximum here)
                    expected_runtime=self._max_repetitions * chunk_count * (
                            self._chunk_delay_seconds + seconds_per_chunk),
                    expected_success=.95  # Pretty unsure, not enough data
                )
            except Exception:
                # Scapy interface not present
                return False
        return False

    def run(self, inputs: [AutosecRessource]) -> [AutosecRessource]:
        """
        Run the attack

        :param inputs: The inputs (InternetDevice, PortRange)
        :return: The results (InternetService)
        """
        # Get device, interface and port range from input resources
        internet_device: InternetDevice = self.get_ressource(inputs, Type[InternetDevice])
        internet_interface: InternetInterface = internet_device.get_interface()
        port_range: PortRange = self.get_ressource(inputs, Type[PortRange])

        # Set target ether object
        target_ether: Ether = Ether(dst=internet_device.get_mac())

        # Init open port list
        discovered_ports: [InternetService] = []

        # Port saving
        ports_left: [int] = list(range(port_range.get_start(), port_range.get_end() + 1))
        ports_retry: [int] = []

        # Go through repetitions
        for repetition in range(1, self._max_repetitions + 1):
            # Go through ports until empty
            while ports_left:
                # Pop next chunk
                chunk: [int] = ports_left[:self._chunk_size]
                ports_left = ports_left[self._chunk_size:]

                # Send packets and get response
                ports_open, ports_not_found = self.send_packets_tcp_syn(
                    network_interface=internet_interface.get_scapy_interface(),
                    target_ip=internet_device.get_ipv4(),
                    target_mac=target_ether,
                    port_list=chunk)

                # Save open ports and not found ports
                for p in ports_open:
                    self._logger.warning(f"Port scanner found open port for device '{internet_device.get_ipv4()}': {p}")
                    discovered_ports.append(InternetService(device=internet_device, port=p))
                ports_retry.extend(ports_not_found)

            # Refill ports
            if ports_retry:
                ports_left, ports_retry = ports_retry, []
            else:
                break

        # Return result
        self._logger.info(f"Port scanner done. Open ports found: {len(discovered_ports)}")
        return discovered_ports

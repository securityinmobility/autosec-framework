import asyncio
import socket
import struct
import ipaddress
from scapy.all import conf
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.base import AutosecRessource
from autosec.core.ressources.ip import InternetDevice, InternetInterface, InternetService
from typing import List, Optional, Tuple
from asyncio import DatagramProtocol, DatagramTransport
 
 
 
class UDPClient(DatagramProtocol):
 
    def __init__(self, iface: str):
        self.iface = iface
        self._transport: Optional[DatagramTransport] = None
        self._rcv_queue: asyncio.Queue = asyncio.Queue()
        self.received_data = {}
 
    @staticmethod
    def _create_socket(iface: str) -> socket.socket:
        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl = struct.pack("@i", 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        interface_index = socket.if_nametoindex(iface)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
        return sock
 
    async def start(self):
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            protocol_factory=lambda: self,
            sock=self._create_socket(self.iface),
        )
 
    async def send_broadcast(self):
        BROADCAST_PACKET = bytes.fromhex("01fe9000000000021000")
        SDP_MULTICAST_GROUP = 'ff02::1'
        UDP_PORT = 15118
        self._transport.sendto(BROADCAST_PACKET, (SDP_MULTICAST_GROUP, UDP_PORT))
        print(f"\nSent broadcast packet to {SDP_MULTICAST_GROUP}:{UDP_PORT}")
 
    def datagram_received(self, data: bytes, addr: Tuple[str, int, int, int]):
        ipv6_address, port, flowinfo, scope_id = addr
        data_hex = data.hex()
        self._rcv_queue.put_nowait((data, addr))
        self.received_data[ipv6_address] = data_hex
 
    def error_received(self, exc):
        print(f"Error received: {exc}")
 
    def connection_lost(self, exc):
        print(f"Connection closed: {exc}")
 
    @staticmethod
    def parse_response(data_hex):
        data = bytes.fromhex(data_hex)
 
        if len(data) < 28:
            raise ValueError("Data too short to contain all necessary fields")
 
        version = data[0]
        msg_type = data[1]
        msg_length = int.from_bytes(data[2:4], byteorder='big')
        reserved = int.from_bytes(data[4:8], byteorder='big')
        ip_address = ipaddress.IPv6Address(data[8:24])
        port = int.from_bytes(data[24:26], byteorder='big')
        security = data[26]
        protocol = data[27]
 
        decoded_message = {
            'Version': version,
            'Message Type': msg_type,
            'Message Length': msg_length,
            'Reserved': reserved,
            'SECC IP Address': str(ip_address),
            'SECC Port': port,
            'Security': security,
            'Transport Protocol': protocol,
        }
 
        return decoded_message
 
 
 
class EVChargingStationFinder(AutosecModule):
 
    def __init__(self):
        super().__init__()
 
    def get_info(self):
        return AutosecModuleInformation(
            name = "EVChargingStationFinder",
            description = "Module to find EV-Charging Stations using UDP broadcast.",
            dependencies=[],
            tags = ["IP", "EV-Charging", "UDP", "Scan"],
        )
 
    def get_produced_outputs(self) -> List[InternetService]:
        return [InternetService]
 
    def get_required_ressources(self) -> List[AutosecRessource]:
        return [InternetDevice]
 
    async def run_exploit(self, iface: str) -> List[InternetService]:
        loop = asyncio.get_running_loop()
 
        udp_listen_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udp_listen_socket.bind(('::', 15119))
        udp_listen_socket.setblocking(True)
 
        udp_client = UDPClient(iface)
        await udp_client.start()
        await udp_client.send_broadcast()
 
        processed_responses = set()
 
        await asyncio.sleep(5)
 
        services = []
        while not udp_client._rcv_queue.empty():
            broadcast_data, addr = await udp_client._rcv_queue.get()
            response_hex = broadcast_data.hex()
            if response_hex in processed_responses:
                continue
 
            processed_responses.add(response_hex)
 
            try:
                response = UDPClient.parse_response(response_hex)
                service = InternetService(
                    device=InternetDevice(
                        interface=InternetInterface(
                            interface=iface,
                            ipv4_address="", # Since it's IPv6, we can leave this blank
                            subnet_length=64  # Assuming a default subnet length
                        ),
                        ipv6=response['SECC IP Address']
                    ),
                    port=response['SECC Port'],
                    service_name="EV-Charging Station"
                )
                services.append(service)
            except ValueError as e:
                print(f"Failed to parse response: {e}")
 
        return services
 
    def run(self, inputs: List[AutosecRessource]) -> List[InternetService]:
        interface = self.get_ressource(inputs, InternetInterface)
        iface = interface.get_interface_name()
        return asyncio.run(self.run_exploit(iface))
 
# Provide module to the framework
def load_module():
    return [EVChargingStationFinder()]
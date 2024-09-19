from scapy.all import conf
from autosec.core.ressources.ip import InternetInterface, InternetService, InternetDevice
from autosec.core.ressources.base import AutosecRessource
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from typing import List, Optional, Tuple
from asyncio import DatagramProtocol, DatagramTransport
import socket
import struct
import asyncio
import ipaddress

# Define a UDP client class for communication
class UDPClient(DatagramProtocol):
    # Initialize the UDP client with a network interface
    def __init__(self, iface: str):
        self.iface = iface  # Store the network interface name
        self._transport: Optional[DatagramTransport] = None  # Will hold the transport for sending/receiving data
        self._rcv_queue: asyncio.Queue = asyncio.Queue()  # Queue to handle received data asynchronously
        self.received_data = {}  # Dictionary to store received data keyed by IPv6 address

    # Static method to create and configure a socket for IPv6 UDP communication
    @staticmethod
    def _create_socket(iface: str) -> socket.socket:
        # Create an IPv6 UDP socket
        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        # Allow address reuse
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set the TTL (Time To Live) for multicast packets to 1 (restrict to local network)
        ttl = struct.pack("@i", 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        # Get the index of the network interface
        interface_index = socket.if_nametoindex(iface)
        # Set the interface to be used for outgoing multicast packets
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
        return sock

    # Start the UDP client and set up the transport layer
    async def start(self):
        loop = asyncio.get_running_loop()
        # Create a datagram endpoint using the custom socket
        self._transport, _ = await loop.create_datagram_endpoint(
            protocol_factory=lambda: self,
            sock=self._create_socket(self.iface),
        )

    # Send a broadcast packet to discover EV-Charging stations
    async def send_broadcast(self):
        # Predefined broadcast packet to send
        BROADCAST_PACKET = bytes.fromhex("01fe9000000000021000")
        SDP_MULTICAST_GROUP = 'ff02::1'  # IPv6 multicast group for all nodes on the local network
        UDP_PORT = 15118  # UDP port to send the packet to
        # Send the packet via the transport layer
        self._transport.sendto(BROADCAST_PACKET, (SDP_MULTICAST_GROUP, UDP_PORT))
        print(f"\nSent broadcast packet to {SDP_MULTICAST_GROUP}:{UDP_PORT}")

    # Handle received datagrams
    def datagram_received(self, data: bytes, addr: Tuple[str, int, int, int]):
        ipv6_address, port, flowinfo, scope_id = addr  # Unpack the address information
        data_hex = data.hex()  # Convert the data to hexadecimal
        self._rcv_queue.put_nowait((data, addr))  # Put the received data in the queue
        self.received_data[ipv6_address] = data_hex  # Store the data associated with the IPv6 address

    # Handle errors that occur during transmission/reception
    def error_received(self, exc):
        print(f"Error received: {exc}")

    # Handle connection loss events
    def connection_lost(self, exc):
        print(f"Connection closed: {exc}")

    # Static method to parse the received response data
    @staticmethod
    def parse_response(data_hex):
        data = bytes.fromhex(data_hex)  # Convert the hexadecimal string back to bytes

        if len(data) < 28:  # Check if the data length is sufficient
            raise ValueError("Data too short to contain all necessary fields")

        # Extract fields from the received data
        version = data[0]
        msg_type = data[1]
        msg_length = int.from_bytes(data[2:4], byteorder='big')
        reserved = int.from_bytes(data[4:8], byteorder='big')
        ip_address = ipaddress.IPv6Address(data[8:24])  # Extract IPv6 address
        port = int.from_bytes(data[24:26], byteorder='big')  # Extract port number
        security = data[26]
        protocol = data[27]

        # Return a dictionary with the parsed fields
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

# Define the Autosec module class for finding EV charging stations
class EVChargingStationFinder(AutosecModule):

    # Initialize the module
    def __init__(self):
        super().__init__()

    # Provide information about the module
    def get_info(self):
        return AutosecModuleInformation(
            name="EVChargingStationFinder",  # Name of the module
            description="Module to find EV-Charging Stations using UDP broadcast.",  # Description of the module
            dependencies=[],  # Dependencies (none in this case)
            tags=["IP", "EV-Charging", "UDP", "Scan"],  # Tags associated with the module
        )

    # Define the outputs produced by the module
    def get_produced_outputs(self) -> List[InternetService]:
        return [InternetService]  # The module outputs a list of InternetService objects

    # Define the resources required by the module
    def get_required_ressources(self) -> List[AutosecRessource]:
        return [InternetInterface]  # The module requires an InternetInterface resource

    # Run the exploit to find EV charging stations
    async def run_exploit(self, iface: str) -> List[InternetService]:
        loop = asyncio.get_running_loop()

        # Create a socket to listen for UDP responses on port 15119
        udp_listen_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        udp_listen_socket.bind(('::', 15119))  # Bind to all IPv6 addresses on port 15119
        udp_listen_socket.setblocking(True)  # Set the socket to blocking mode

        # Create a UDP client and start it
        udp_client = UDPClient(iface)
        await udp_client.start()
        await udp_client.send_broadcast()  # Send the broadcast packet

        processed_responses = set()  # Set to keep track of processed responses

        await asyncio.sleep(5)  # Wait for 5 seconds to receive responses

        services = []
        # Process each received response
        while not udp_client._rcv_queue.empty():
            broadcast_data, addr = await udp_client._rcv_queue.get()
            response_hex = broadcast_data.hex()
            if response_hex in processed_responses:  # Skip already processed responses
                continue

            processed_responses.add(response_hex)

            try:
                # Parse the response and create an InternetService object
                response = UDPClient.parse_response(response_hex)
                service = InternetService(
                    device=InternetDevice(
                        interface=InternetInterface(
                            interface=iface,
                            ipv4_address="",  # Not used, as we are dealing with IPv6
                            subnet_length=64  # Assuming a default subnet length
                        ),
                        ipv6=response['SECC IP Address']  # Assign the parsed IPv6 address
                    ),
                    port=response['SECC Port'],  # Assign the parsed port
                    service_name="EV-Charging Station"  # Assign a service name
                )
                services.append(service)  # Add the service to the list
            except ValueError as e:
                print(f"Failed to parse response: {e}")  # Handle any errors during parsing

        return services  # Return the list of discovered services

    # Run the module and return the discovered services
    def run(self, inputs: List[AutosecRessource]) -> List[InternetService]:
        interface = self.get_ressource(inputs, InternetInterface)  # Get the network interface resource
        iface = interface.get_interface_name()  # Get the interface name
        services = asyncio.run(self.run_exploit(iface))  # Run the exploit and get services
    
        if services and len(services) > 0:
            print(f"\nCharging Station Found: \n")
        else:
            print(f"\nNo Charging Station Found.\n")
        
        return services  # Return the discovered services

# Provide the module to the Autosec framework
def load_module():
    return [EVChargingStationFinder()]  # Return the module instance



'''
test.py

from autosec.core.ressources.ip import InternetInterface
from autosec.modules.ev_charging_station_discovery import EVChargingStationFinder

inet_iface = InternetInterface("eth0", ipv4_address="0.0.0.0", subnet_length=20)

results = EVChargingStationFinder().run([inet_iface])

for result in results:
    secc_ip = result.get_device().get_ipv6()
    tcp_port = result.get_port()
    print(f"IP Address of the Charging Station: {secc_ip}")
    print(f"\nTCP Port number of the Charging Station: {tcp_port}\n")

'''
 
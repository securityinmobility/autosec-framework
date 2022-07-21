import socket

from scapy.interfaces import NetworkInterface as NetInterface

from .base import AutosecRessource, NetworkInterface
from typing import Optional


class InternetInterface(NetworkInterface):
    """
    Internet network interface ressource
    """

    _ipv4_address: str
    _subnet_length: int
    _scapy_interface: Optional[NetInterface]

    def __init__(self, interface, ipv4_address: str, subnet_length: int, scapy_interface: NetInterface = None):
        """
        :param interface: Interface name
        :param ipv4_address: Local ipv4 address of the current device
        :param subnet_length: Int representation of subnet mask (e.g. 24 for 255.255.255.0 od 16 for 255.255.0.0)
        :param scapy_interface: Scapy network interface object
        """
        super().__init__(interface)
        self._ipv4_address = ipv4_address
        self._subnet_length = subnet_length
        self._scapy_interface = scapy_interface

    def get_network_address(self) -> str:
        """
        :return: Network address with subnet length
        """
        return f"{self._ipv4_address}/{self._subnet_length}"

    def get_ipv4_address(self) -> str:
        """
        :return: Local ipv4 address of framework
        """
        return self._ipv4_address

    def get_subnet_length(self) -> int:
        """
        :return: Subnet mask as int representation (e.g. 24 for 255.255.255.0 od 16 for 255.255.0.0)
        """
        return self._subnet_length

    def get_scapy_interface(self) -> Optional[NetInterface]:
        """
        :return: The optional scapy network interface object
        """
        return self._scapy_interface


class InternetDevice(AutosecRessource):
    _interface: InternetInterface
    _ipv4: Optional[str]
    _ipv6: Optional[str]
    _mac: Optional[str]
    _manufacturer: Optional[str]

    def __init__(self, interface: InternetInterface, ipv4: str = None, ipv6: str = None, mac: str = None,
                 manufacturer: str = None):
        """
        :param mac: The MAC address of the device
        :param manufacturer: The manufacturer of the device
        """
        self._interface = interface
        self._ipv4 = ipv4
        self._ipv6 = ipv6
        self._mac = mac
        self._manufacturer = manufacturer

    def get_interface(self) -> InternetInterface:
        return self._interface

    def get_ipv4(self) -> str:
        if self._ipv4 is None:
            raise ValueError("Trying to get non existent IPv4 from an InternetDevice")

        return self._ipv4

    def get_ipv6(self) -> str:
        if self._ipv6 is None:
            raise ValueError("Trying to get non existent IPv6 from an InternetDevice")

        return self._ipv6

    def get_address(self) -> str:
        if self._ipv4 is not None:
            return self._ipv4
        elif self._ipv6 is not None:
            return self._ipv6
        else:
            raise ValueError("Trying to get non existent Address from an InternetDevice")

    def set_mac(self, mac: str):
        """
        :param mac: The new MAC address
        """
        self._mac = mac

    def get_mac(self) -> str:
        """
        :return: The MAC address
        """
        if self._mac is None:
            raise ValueError("Trying to get non existent MAC from an InternetDevice")
        return self._mac

    def set_manufacturer(self, manufacturer: str):
        """
        :param manufacturer: The new manufacturer
        """
        self._manufacturer = manufacturer

    def get_manufacturer(self) -> str:
        """
        :return: The manufacturer
        """
        if self._manufacturer is None:
            raise ValueError("Trying to get non existent manufacturer from an InternetDevice")
        return self._manufacturer


class PortRange(AutosecRessource):
    """
    A range of ports used for tcp scanning
    """
    _start: int
    _end: int

    def __init__(self, start: int = 1, end: int = 65535):
        """
        :param start: The start port (included)
        :param end: The end port (included)
        """
        self._start = start
        self._end = end

    def get_start(self) -> int:
        """
        :return: The start port
        """
        return self._start

    def get_end(self) -> int:
        """
        :return: The end port
        """
        return self._end


class InternetService(AutosecRessource):
    _device: InternetDevice
    _port: int
    _service_name: str

    def __init__(self, device: InternetDevice, port: int, service_name = "unknown"):
        self._device = device
        self._port = port
        self._service_name = service_name

    def get_device(self) -> InternetDevice:
        return self._device

    def get_port(self) -> int:
        return self._port

    def get_service_name(self):
        return self._service_name

    def connect(self) -> 'InternetConnection':
        return InternetConnection(self)




class InternetConnection(AutosecRessource):
    _service: InternetService
    _socket: socket.socket

    def __init__(self, service: InternetService):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((service.get_device().get_address(), service.get_port()))

    def send(self, data: bytes):
        self._socket.send(data)

    def recv(self, amount: int):
        self._socket.recv(amount)

    def read_until(self, stop = b'\n'):
        result = b''
        while True:
            curr = self.recv(1)
            result += curr

            if curr == stop:
                return result

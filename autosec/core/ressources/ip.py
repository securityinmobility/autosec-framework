
import socket
from typing import Optional

from scapy.interfaces import NetworkInterface as NetInterface

from .base import AutosecRessource, NetworkInterface


class InternetInterface(NetworkInterface):
    """
    Internet network interface ressource
    """

    def __init__(self, interface, ipv4_address: str, subnet_length: int, scapy_interface: NetInterface = None):
        """
        :param interface: Interface name
        :param ipv4_address: Local ipv4 address of the current device
        :param subnet_length: Int representation of subnet mask (e.g. 24 for 255.255.255.0 od 16 for 255.255.0.0)
        :param scapy_interface: Scapy network interface object
        """
        super().__init__(interface)
        self._ipv4_address: str = ipv4_address
        self._subnet_length: int = subnet_length
        self._scapy_interface: Optional[NetInterface] = scapy_interface

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

    def get_scapy_interface(self) -> NetInterface:
        """
        :return: The optional scapy network interface object
        """
        if not self._scapy_interface:
            raise ValueError("Trying to get non existent scapy interface from an InternetInterface")
        return self._scapy_interface

    def __eq__(self, other) -> bool:
        return self.get_network_address() == other.get_network_address()



class InternetDevice(AutosecRessource):
    """
    Internet device ressource
    """

    def __init__(self, interface: InternetInterface, ipv4: str = None, ipv6: str = None, mac: str = None,
                 manufacturer: str = None):
        """
        :param interface: The interface to reach the device
        :param ipv4: The ipv4 address of the device
        :param ipv6: The ipv6 address of the device
        :param mac: The MAC address of the device
        :param manufacturer: The manufacturer of the device
        """
        self._interface: InternetInterface = interface
        self._ipv4: Optional[str] = ipv4
        self._ipv6: Optional[str] = ipv6
        self._mac: Optional[str] = mac
        self._manufacturer: Optional[str] = manufacturer

    def get_interface(self) -> InternetInterface:
        """
        :return: The interface to reach the device
        """
        return self._interface

    def get_ipv4(self) -> str:
        """
        :return: The ipv4 address of the device
        """
        if self._ipv4 is None:
            raise ValueError("Trying to get non existent IPv4 from an InternetDevice")
        return self._ipv4

    def get_ipv6(self) -> str:
        """
        :return: The ipv6 address of the device
        """
        if self._ipv6 is None:
            raise ValueError("Trying to get non existent IPv6 from an InternetDevice")
        return self._ipv6

    def get_address(self) -> str:
        """
        :return: The ipv4 address of the device and if not found the ipv6
        """
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

    def __eq__(self, other) -> bool:
        tmp_1 = self.get_interface().__eq__(other.get_interface())
        tmp_2 = self.get_address() == other.get_address()
        return tmp_1 and tmp_2

class PortRange(AutosecRessource):
    """
    A range of ports used for tcp scanning
    """

    def __init__(self, start: int = 1, end: int = 65535):
        """
        :param start: The start port (included)
        :param end: The end port (included)
        """
        self._start: int = start
        self._end: int = end

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
    """
    Internet service ressource
    """

    def __init__(self, device: InternetDevice, port: int, service_name="unknown"):
        """
        :param device: The device that provides the service
        :param port: The port of the service
        :param service_name: The name of the service
        """
        self._device: InternetDevice = device
        self._port: int = port
        self._service_name: str = service_name

    def get_device(self) -> InternetDevice:
        """
        :return: The device that provides the service
        """
        return self._device

    def get_port(self) -> int:
        """
        :return: The port of the service
        """
        return self._port

    def get_service_name(self):
        """
        :return: The name of the service
        """
        return self._service_name

    def connect(self) -> 'InternetConnection':
        """
        Connect to the service

        :return: The connection to the service
        """
        return InternetConnection(self)

    def __eq__(self, other) -> bool:
        tmp_1 = self.get_device().__eq__(other.get_device())
        tmp_2 = self.get_port() == other.get_port()
        return tmp_1 and tmp_2


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

    def read_until(self, stop=b'\n'):
        result = b''
        while True:
            curr = self.recv(1)
            result += curr

            if curr == stop:
                return result


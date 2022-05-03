import socket
from base import AutosecRessource, NetworkInterface
from typing import Optional

class InternetInterface(NetworkInterface):
    pass

class InternetDevice(AutosecRessource):
    _interface: InternetInterface
    _ipv4: Optional[str]
    _ipv6: Optional[str]

    def __init__(self, interface: InternetInterface, ipv4: str = None, ipv6: str = None):
        self._interface = interface
        self._ipv4 = ipv4
        self._ipv6 = ipv6

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

class InternetService(AutosecRessource):
    _device: InternetDevice
    _port: int

    def __init__(self, device: InternetDevice, port: int):
        self._device = device
        self._port = port

    def get_device(self) -> InternetDevice:
        return self._device
    
    def get_port(self) -> int:
        return self._port

    def connect(self) -> 'InternetConnection':
        return InternetConnection(self)

class InternetConnection(AutosecRessource):
    _service: InternetService
    _socket: socket.socket

    def __init__(self, service: InternetService):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((service.get_device().get_address(), service.get_port()))

    def send(data: bytes):
        self._socket.send(data)

    def recv(amount: int):
        self._socket.recv(amount)

    def read_until(stop = b'\n'):
        result = b''
        while True:
            curr = self.recv(1)
            result += curr

            if curr == stop:
                return result

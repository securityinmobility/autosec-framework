import socket
from .base import AutosecRessource, NetworkInterface
from typing import Optional



class InternetInterface(NetworkInterface):
    #pass

    network_addr: Optional[str]

    def __init__(self, interface, network_addr: str=""):
        super().__init__(interface)
        self.network_addr = network_addr
    
    def get_network_address(self):
        return self.network_addr



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

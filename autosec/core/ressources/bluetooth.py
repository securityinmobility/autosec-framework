from .base import AutosecRessource, NetworkInterface
from typing import Optional
import socket
from scapy.layers.bluetooth import BluetoothL2CAPSocket


class BluetoothInterface(NetworkInterface):
    #pass

    bd_addr: Optional[str]

    def __init__(self, interface, bd_addr: str=""):
        super().__init__(interface)
        self.bd_addr = bd_addr
    
    def get_network_address(self):
        return self.bd_addr
    

class BluetoothDevice(AutosecRessource):
    _interface: BluetoothInterface
    _bd_addr: str
    _bd_name: Optional[str]

    def __init__(self, interface: BluetoothInterface, bd_addr: str, bd_name: str = None):
        self._interface = interface
        self._bd_addr = bd_addr
        self._bd_name = bd_name

    def get_interface(self) -> BluetoothInterface:
        return self._interface
    
    def get_bd_addr(self) -> str:
        return self._bd_addr
    
    def get_bd_name(self) -> str:
        if self._bd_name is None:
             raise ValueError("Name of the device is not defined")
        return self._bd_name
    
class BluetoothService(AutosecRessource):
    _device: BluetoothDevice
    _protocol: str
    _port: int
    _service_name: str

    def __init__(self, device: BluetoothDevice, protocol: str, port: int, service_name: str):
        self._device = device
        protocol_upper_case = protocol.strip().upper()
        if protocol_upper_case == "RFCOMM" or protocol_upper_case == "L2CAP":
            self._protocol = protocol_upper_case
        else:
            raise ValueError(f"Protocol is not RFCOMM or L2CAP")
        self._port = port
        self._service_name = service_name

    def get_device(self) -> BluetoothDevice:
        return self._device
    
    def get_protocol(self) -> str:
        return self._protocol
    
    def get_port(self) -> int:
        return self._port
    
    def get_service_name(self) -> str:
        return self._service_name
    
    def connect(self) -> 'BluetoothConnection':
        return BluetoothConnection(self)
    
class BluetoothConnection(AutosecRessource):
    _service = BluetoothService
    _bt_socket = socket.socket

    def __init__(self, service: BluetoothService):
        self._service = service
        if self._service.get_protocol() == "L2CAP":
            self._socket = BluetoothL2CAPSocket(service.get_device().get_bd_addr()) # Scapy's L2CAP Socket always used port 0, maybe new implementatione needed
        if self._service.get_protocol() == "RFCOMM":
            self._socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
            self._socket.connect(service.get_device().get_bd_addr(), service.get_port)

    def send(self, data):
        self._socket.send(data)

    def recv(self, amount: int):
        self._socket.recv(amount)

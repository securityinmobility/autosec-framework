from .base import AutosecRessource, NetworkInterface
from typing import Optional
import socket
from scapy.layers.bluetooth import BluetoothL2CAPSocket
import bluetooth
import subprocess
import time
import os
from typing import List


class BluetoothInterface(NetworkInterface):
    #pass

    bd_addr: str

    def __init__(self, interface, bd_addr: str):
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
    
class BTImitationDevice(BluetoothDevice):
    _old_address: str
    _old_name: str

    def __init__(self, interface: BluetoothInterface, bd_addr: str, old_address: str, bd_name: str, old_name: str):
        super().__init__(interface, bd_addr, bd_name)
        self._old_address = old_address
        self._old_name = old_name

    def get_old_address(self):
        return self._old_address
    
    def get_old_name(self):
        return self._old_name

    def __del__(self):
        interface_name = self.get_interface().get_interface_name()
        print(interface_name)
        print("resetting name and address")
        # reset name and mac
        if os.path.isfile("/etc/machine-info"):
            with open("/etc/machine-info", "r") as file:
                lines = file.readlines()

        with open("/etc/machine-info", "w") as file:
            for line in lines:
                if line.startswith("PRETTY_HOSTNAME"):
                    file.write(f"PRETTY_HOSTNAME={self._old_name}")
                else:
                    file.write(line)

        subprocess.run(["service", "bluetooth", "restart"])
        time.sleep(1)
        subprocess.run(["bdaddr", "-i", interface_name, "-r", self._old_address])
        time.sleep(1)
        subprocess.run(["hciconfig", interface_name, "up"])
    
class BluetoothService(AutosecRessource):
    _device: BluetoothDevice
    _protocol: str
    _port: int
    _service_name: Optional[str]

    def __init__(self, device: BluetoothDevice, protocol: str, port: int, service_name: str = None):
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
            self._socket = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            self._socket.connect((service.get_device().get_bd_addr(), service.get_port()))
        if self._service.get_protocol() == "RFCOMM":
            self._socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self._socket.connect((service.get_device().get_bd_addr(), service.get_port()))

    def send(self, data):
        self._socket.send(data)

    def recv(self, amount: int):
        self._socket.recv(amount)

class FileData(AutosecRessource):
    _filename = str
    _data = bytes

    def __init__(self, filename: str, data: bytes):
        self._filename = filename
        self._data = data

    def get_filename(self):
        return self._filename
    
    def get_data(self):
        return self._data

    def write_to_file(self, path):
        if not path is None:
            with open(f"{path}/{self._filename}", "wb") as binary_file:
                binary_file.write(self._data)
                binary_file.close()
        else:
            with open(self._filename, "wb") as binary_file:
                binary_file.write(self._data)
                binary_file.close()

class VCard(AutosecRessource):
    _version: float
    _name: str
    _full_name: str
    _tel: Optional[List[str]]
    _email: Optional[List[str]]
    _birthday: Optional[str]

    def __init__(self, version: float, name: str, full_name: str, tel: List[str] = None, email: List[str] = None, birthday: str = None):
        self._version = version
        self._name = name
        self._full_name = full_name
        self._tel = tel
        self._email = email
        self._birthday = birthday

    def get_version(self):
        return self._version
    
    def get_name(self):
        return self._name
    
    def get_full_name(self):
        return self._full_name
    
    def get_tel(self):
        if self._tel is None:
            raise ValueError("Telephone number is not defined")
        return self._tel
    
    def get_email(self):
        if self._email is None:
            raise ValueError("Email is not defined")
        return self._email
    
    def get_birthday(self):
        if self._birthday is None:
            return "Birthday is not defined"
        return self._birthday
        

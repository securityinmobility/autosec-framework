from base import AutosecRessource, NetworkInterface
from scapy.layers.can import CAN
from scapy.contrib.cansocket import CANSocket

class CanInterface(NetworkInterface):
    def __init__(self, interface_name: str):
        super().__init__(interface_name)
        self._interface = CANSocket(channel=interface_name)

    def send_message(msg_id: int, data: bytes):
        msg = CAN(identifier=msg_id, length=len(data), data=data)
        self._interface.send(msg)

class CanDevice(AutosecRessource):
    _interface: CanInterface
    _address: int

    def __init__(self, interface: CanInterface, address: int):
        self._interface = interface
        self._address = address

    def get_interface(self) -> CanInterface:
        return self._interface

    def get_address(self) -> int:
        return self._address

    def request_data():
        pass # TODO remote transmission request

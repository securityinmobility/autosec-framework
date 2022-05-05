from .base import AutosecRessource, NetworkInterface
from scapy.layers.can import CAN
from scapy.contrib.cansocket import CANSocket

class CanInterface(NetworkInterface):
    _interface: CANSocket

    def __init__(self, interface_name: str):
        super().__init__(interface_name)
        self._interface = CANSocket(channel=interface_name)

    def get_socket(self) -> CANSocket:
        return self._interface

    def send_message(self, msg_id: int, data: bytes):
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

class IsoTPService(AutosecRessource):
    _interface: CanInterface
    _tx_id: int
    _rx_id: int

    def __init__(self, interface: CanInterface, tx_id: int, rx_id: int):
        super().__init__()
        self._interface = interface
        self._tx_id = tx_id
        self._rx_id = rx_id

    def get_interface(self) -> CanInterface:
        return self._interface

    def get_tx_id(self) -> int:
        return self._tx_id

    def get_rx_id(self) -> int:
        return self._rx_id

    def get_socket(self) -> 'ISOTPSocket':
        return ISOTPSocket(self._interface, self._tx_id, self._rx_id)

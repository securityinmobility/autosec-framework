
from autosec.core.ressources.base import AutosecRessource, NetworkInterface
from scapy.all import conf, load_contrib

conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
conf.contribs['CANSocket'] = {'use-python-can': False}
load_contrib('cansocket')
load_contrib('isotp')

from scapy.layers.can import CAN
from scapy.contrib.cansocket_native import CANSocket


class CanInterface(NetworkInterface):
    _interface: CANSocket

    def __init__(self, interface_name: str):
        super().__init__(interface_name)
        self._interface_name = interface_name
        self._interface = CANSocket(interface_name)

    def get_socket(self) -> CANSocket:
        return self._interface

    def send_message(self, msg_id: int, data: bytes):
        msg = CAN(identifier=msg_id, length=len(data), data=data)
        self._interface.send(msg)

    def __eq__(self, other) -> bool:
        return self.get_interface_name() == other.get_interface_name()

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

    def __eq__(self, other) -> bool:
        tmp1 = self.get_interface().__eq__(other.get_interface())
        tmp2 = self.get_address() == other.get_address()
        return tmp1 and tmp2

class CanOverride(AutosecRessource):

    def __init__(self, indexStart: int, values: bytes):
        super().__init__()
        self.start = indexStart
        self.values = values

    def change_data(self, data: bytes) -> bytes:
        if type(self.values) != bytes:
            raise Exception("Values have to be bytes.")
        if self.start + len(self.values) > 8:
            raise Exception("Only 8 bytes")
        data = list(data)
        values = list(self.values)
        new_data = data[:self.start] + values + data[self.start+len(values)::]
        return bytes(new_data)  


class CanService(AutosecRessource):

    def __init__(self, service, data):
        super().__init__()
        self.service = service
        self.data = data
    
    def get_data(self):
        return self.data
    
    def get_service(self):
        return self.service

    def __eq__(self, other) -> bool:
        print(type(self), type(other))
        tmp1 = self.get_data() == other.get_data()
        tmp2 = self.get_service() == other.get_service()
        return tmp1 and tmp2



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
        return ISOTPSocket(self._interface.get_socket(), self._tx_id, self._rx_id)

    def __eq__(self, other) -> bool:
        tmp_1 = self.get_interface().__eq__(other.get_interface()) 
        tmp_2 = self.get_tx_id() == other.get_tx_id()
        tmp_3 = self.get_rx_id() == other.get_rx_id()
        return tmp_1 and tmp_2 and tmp_3


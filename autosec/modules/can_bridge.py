'''
Module to provide sniffing and manipulation of CAN networks.
This attack works as a MITM with two CAN interfaces.
Usually, all messages are transferred between the interfaces, but some
messages (e.g. with certain IDs) can be manipulated.
'''
import threading
<<<<<<< HEAD
import logging
from scapy.all import load_layer, load_contrib
from scapy.layers.can import CAN
from scapy.contrib.cansocket import CANSocket

=======
from scapy.all import load_contrib, load_layer
>>>>>>> feature/can_bridge
from autosec.core.autosec_module import AutosecModule

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [CanBridge()]


class CanBridge(AutosecModule):
    '''
    Class that implements the MITM attack
    '''
    def __init__(self):
        super().__init__()

        #self.logger = logging.getLogger("autosec.modules.can_bridge")
        #self.logger.setLevel(logging.DEBUG)

        self._add_option("primaryInterface",
            description="First Interface of the CAN Bridge",
            required = True)

        self._add_option("secondaryInterface",
            description="Second Interface of the CAN Bridge",
            required = True)

        self._add_option("filters",
            description = "Filters that can intercept the communication",
            required = True,
            default = ([],[]))

<<<<<<< HEAD
        self.logger = logging.getLogger("autosec.modules.can_bridge")
        self.logger.setLevel(logging.DEBUG)

        self.interfaces = dict(
            primaryInterface = dict(name = "primaryInterface",
                required = True,
                default = None,
                unit = "SocketCAN Device Name",
                range = None,
                value = None),
            secondaryInterface = dict(name = "secondaryInterface",
                required = True,
                default = None,
                unit = "SocketCAN Device Name",
                range = None,
                value = None)
            )

        load_layer("can")
        load_contrib("cansocket")

        self.primary_interface = CANSocket(channel = "vcan0")
        self.secondary_interface = CANSocket(channel = "vcan1")
        self.filters = ([], [])
        self.thread = None

=======
        load_layer("can")
        load_contrib("cansocket")

        self.primary_interface = None
        self.secondary_interface = None

        self.primary_thread = threading.Thread(target=self._primary_message)
        self.secondary_thread = threading.Thread(target=self._secondary_message)

>>>>>>> feature/can_bridge
    def get_info(self):
        return(dict(
            name = "canBridge",
            source = "autosec",
            type = "mitm",
            interface = "CAN",
            description = "Module to perform MITM CAN attacks with two CAN interfaces"))

<<<<<<< HEAD
    def get_options(self):
        return self.interfaces.copy()

    def set_options(self, options):
        raise NotImplementedError

    def run(self):
        self.logger.debug("Starting the bridge..")
        self.thread = threading.Thread(target=self._sniff)
        self.thread.start()

    def _sniff(self):
        self.primary_interface.sniff(prn=self._primary_message)
        self.secondary_interface.sniff(prn=self._secondary_message)

    def _primary_message(self, pkt):
        self._on_message(0, pkt.identifier, pkt.data)

    def _secondary_message(self, pkt):
        self._on_message(1, pkt.identifier, pkt.data)

    def _on_message(self, interface, msg_id, data):
        '''
        # list to carry the messages to be intercepted
        # ID IF1, Answer IF1, ID IF2, Answer IF2eceived message.
        self.intercept = [
            (
                0x7af,
                lambda data: b'\x03\x04\x05',
                None,
                lambda data: b'\x06\x07\x08'
            )
        ]
        interface: interface that received message (0 = primary, 1 = secondary)
        id: ID of the received message
        data: data of the received message
        '''
        self.logger.debug("Received message on %s with id %03x and data %s",
            interface, msg_id, data)
        result = (False, None, None)
        for _filter in self.filters[interface]:
            filter_result = _filter(msg_id, data)
=======
    def run(self):
        try:
            super().run()
        except ValueError as error:
            self.logger.warning(error)
            return
        self.logger.info("Accessing CAN interfaces..")

        try:
            self.primary_interface = CANSocket(
                channel = self._options["primaryInterface"]["value"])
            self.secondary_interface = CANSocket(
                channel = self._options["secondaryInterface"]["value"])
        except OSError:
            self.logger.warning("Could not access the CAN Devices.")
            return
        self.logger.info("Starting the bridge..")

        self.primary_thread.start()
        self.secondary_thread.start()

    def stop(self):
        '''
        Stops the started threads.
        #ToDo: Not yet functional
        '''
        self.primary_thread.join()
        self.secondary_thread.join()

    def _primary_message(self):
        '''
        Method to sniff messages on the primary interface
        '''
        self.primary_interface.sniff(prn=lambda pkt: self._on_message(0, pkt.identifier, pkt.data))

    def _secondary_message(self):
        '''
        Method to sniff messages on the primary interface
        '''
        self.secondary_interface.sniff(
            prn=lambda pkt: self._on_message(1, pkt.identifier, pkt.data))

    def _on_message(self,interface, identifier, data):
        '''
        This method involves the given filters on the received messages.
        The interface is provided by "interface" (0 = primary, 1 = secondary),
        the message is given with id and data.
        '''
        self.logger.debug(f"Received message on {interface} with id {identifier} and data {data}")
        result = (False, None, None)
        for msg_filter in self._options["filters"]["value"][interface]:
            filter_result = msg_filter(identifier, data)
>>>>>>> feature/can_bridge
            if filter_result[0]:
                result = filter_result

        if result[0]:
            self._send(self.primary_interface, result[1])
            self._send(self.secondary_interface, result[2])
        else:
            if interface == 0:
<<<<<<< HEAD
                self._send(self.secondary_interface, (msg_id, data))
            else:
                self._send(self.primary_interface, (msg_id, data))

    @staticmethod
    def _send(interface, packet):
=======
                self._send(self.secondary_interface, (identifier, data))
            else:
                self._send(self.primary_interface, (identifier, data))

    @classmethod
    def _send(cls, interface, packet):
>>>>>>> feature/can_bridge
        '''
        Method to send a packet on a specified interface
        '''
        if packet is not None:
<<<<<<< HEAD
            msg_id = packet[0]
            data = packet[1]
            interface.send(CAN(identifier=msg_id, length=len(data), data=data))
=======
            identifier = packet[0]
            data = packet[1]
            interface.send(CAN(identifier=identifier, length=len(data), data=data))
>>>>>>> feature/can_bridge

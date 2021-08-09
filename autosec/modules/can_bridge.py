'''
Module to provide sniffing and manipulation of CAN networks.
This attack works as a MITM with two CAN interfaces.
Usually, all messages are transferred between the interfaces, but some
messages (e.g. with certain IDs) can be manipulated.
'''
import threading
from scapy.all import load_contrib, load_layer
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

        load_layer("can")
        load_contrib("cansocket")

        self.primary_interface = None
        self.secondary_interface = None

        self.primary_thread = threading.Thread(target=self._primary_message)
        self.secondary_thread = threading.Thread(target=self._secondary_message)

    def get_info(self):
        return(dict(
            name = "canBridge",
            source = "autosec",
            type = "mitm",
            interface = "CAN",
            description = "Module to perform MITM CAN attacks with two CAN interfaces"))

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
            if filter_result[0]:
                result = filter_result

        if result[0]:
            self._send(self.primary_interface, result[1])
            self._send(self.secondary_interface, result[2])
        else:
            if interface == 0:
                self._send(self.secondary_interface, (identifier, data))
            else:
                self._send(self.primary_interface, (identifier, data))

    @classmethod
    def _send(cls, interface, packet):
        '''
        Method to send a packet on a specified interface
        '''
        if packet is not None:
            identifier = packet[0]
            data = packet[1]
            interface.send(CAN(identifier=identifier, length=len(data), data=data))

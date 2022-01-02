'''
Load CAN_Util Module
'''

from autosec.core.autosec_module import AutosecModule
from enum import Enum
from autosec.modules.CAN_Util import ethernet_connection

'''
This is the basic interface that has to be implemented by all adapters that introduce
modules to the autosec framework. This module also introduces some functionality, that
may help to create modules faster.
'''


class Attack(Enum):
    No_Attack = 0,
    BusFlood = 1,
    Simple_Frame_Spoofing = 2,
    Error_Passive_Spoofing_Attack = 4,
    Double_Receive_Attack = 5,
    Bus_Off_Attack = 6,
    Freeze_Doom_Loop_Attack = 7,


def load_module():
    """
    Method to provide the module to the framework
    """
    return [CanAttackModule()]


class CanAttackModule(AutosecModule):
    """
    Class the modules should inherit from
    """

    def __init__(self):
        super().__init__()
        self._add_option("ip",
                         description="Ip of the FPGA",
                         required=True,
                         default=True,
                         value="192.168.1.10"
                         )

        self._add_option("port",
                         description="Port of the FPGA",
                         required=True,
                         default=True,
                         value="7"
                         )

        self._add_option("attack",
                         description="Attack that hast to be executed",
                         required=True,
                         default=0
                         )

        self._add_option("identifier",
                         description="Identifier to be used in Hexadecimal",
                         required=True,
                         default=0x00
                         )

        self._add_option("data",
                         description="Array with Data to be used in Hexadecimal",
                         required=False,
                         default=[0x11, 0x22, 0x33, 0x44]
                         )

        self.ide = None
        self.dlc = None

    def get_info(self):
        '''
        This method returns information about the module, e.g. name, package / type, interface,
        purpose etc.
        @return: information as dictionary with the following keys:
        name
        source (e.g. msf, autosec, etc.)
        type (e.g. sniffer, scanner, exploit, payload, attack ...)
        interface (e.g. ethernet, CAN, LIN, Flexray ...)
        description (textual description)
        '''
        return (dict(
            name="BusFlood",
            source="autosec",
            type="attack",
            interface="CAN",
            description="Module that implements Attacks on the CAN Bus"))

    def run(self):
        '''
        Method to run the module
        '''

        print(Attack.__members__.items())
        transfer_array = bytearray()

        try:
            super().run()
        except ValueError as error:
            # self.logger.warning(error)
            return error

        if self._options["identifier"]["value"] > 2047:
            self.ide = 1
        elif self._options["identifier"]["value"] > 4294967296:
            raise ValueError(f"Identifier Value of{self._options['identifier']['value']} exceeding the Limit of 32 Bits")
            return -1
        else:
            self.ide = 0

        if len(self._options["data"]["value"]) > 8:
            raise ValueError(f"Data Segment Length of{len(self._options['data']['value'])} exceeding the Limit of 8")
            return -1
        else:
            self.dlc = len(self._options["data"]["value"])

        try:
            print(self._options["ip"]["value"], self._options["port"]["value"])
            socket = ethernet_connection.connect_board(self._options["ip"]["value"], self._options["port"]["value"])
        except socket.error as error:
            raise ConnectionError(
                "Ethernet Connection with [{}] and [{}] could not be established".format(self._options["ip"]["value"],
                                                                                         self._options["port"][
                                                                                             "value"]))
            return-1

        identifier = [((self._options["identifier"]["value"] & 0xFF000000) >> 24),
                      ((self._options["identifier"]["value"] & 0x00FF0000) >> 16),
                      ((self._options["identifier"]["value"] & 0x0000FF00) >> 8),
                      ((self._options["identifier"]["value"] & 0x000000FF) >> 0)]

        transfer_array.append(self._options["attack"]["value"])
        transfer_array.append(self.ide)
        for i in range(4):
            transfer_array.append(identifier[i])
        transfer_array.append(self.dlc)

        for i in range(len(self._options["data"]["value"])):
            transfer_array.append(self._options["data"]["value"][i])

        print(transfer_array)

        socket.send(transfer_array)
        print("Warte auf Antwort")
        receive = socket.recv(1024).decode()
        print(receive)
        # receive = socket.recv(1024).decode()
        # print(receive)
        socket.close()

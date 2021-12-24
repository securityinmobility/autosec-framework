'''
Load Bus_Flood Module
'''

import sys

sys.path.append("S:/Studium/Bachelorarbeit/autosec-framework/autosec/core")

from autosec_module import AutosecModule
from enum import Enum
import ethernet_connection

'''
This is the basic interface that has to be implemented by all adapters that introduce
modules to the autosec framework. This module also introduces some functionality, that
may help to create modules faster.
'''
class Attack(Enum):
    No_Attack = 0,
    BusFlood = 1,
    Simple_Frame_Spoofing = 2,


def load_module():
    """
    Method to provide the module to the framework
    """
    return BusFloodModule


class BusFloodModule(AutosecModule):
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
                         description="Port of the FPGA",
                         required=True,
                         default=True,
                         value="7"
                         )

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

    def get_options(self):
        '''
        return the specific options this module has with a description
        @return: specific options as list of dictionaries with the following keys:
        name (name or ID of the option)
        required (flag if the option is required or not)
        default (default value if available)
        unit (unit of the option)
        range
        description
        value (value that is currently set if so)
        '''
        raise NotImplementedError

    def set_options(self, options):
        '''
        Method to store options for this module. The Options are given within a list of
        tuples with the name and the value.
        TBD: check Range and value of the option (if these requirements are available)
        '''

        raise NotImplementedError

    def run(self):
        '''
        Method to run the module
        '''
        try:
            print(self._options["ip"]["value"], self._options["port"]["value"])
            socket = ethernet_connection.connect_board(self._options["ip"]["value"], self._options["port"]["value"])
        except:
            print("Ethernet Connection with [{}] and [{}] could not be established".format(self._options["ip"]["value"],
                                                                                           self._options["port"][
                                                                                               "value"]))
            return -1
        socket.send("1".encode())
        print("Warte auf Antwort")
        receive = socket.recv(1024).decode()
        print(receive)
        receive = socket.recv(1024).decode()
        print(receive)
        socket.close()

from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothDevice, BluetoothInterface, BluetoothService, BluetoothConnection
from typing import List
import bluetooth
import sys

from autosec.core.ressources.base import AutosecRessource

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [RFCOMMService()]

class RFCOMMService(AutosecModule):
    '''
    Class providing an RFCOMM Scan for on a bluetooth device
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="RFCOMMScan",
            description = "Module to scan for open RFCOMM channels on a bluetooth device.",
            dependencies = [],
            tags = ["Bluetooth", "RFCOMM"]
        )
    
    def get_produced_outputs(self) -> tuple[List[BluetoothService],List[BluetoothService]]:
        return [BluetoothService]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothInterface]
    
    
    def run(self,inputs: List[AutosecRessource]) -> tuple[List[BluetoothService], List[BluetoothService]]:
        
        interface = self.get_ressource(inputs, BluetoothInterface)
        address = interface.get_network_address()
        services = {"open": [], "closed": []}
        for channel in range(1, 31):
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            got_timeout = False
            channel_open = False

            try:
                sock.connect((address, channel))
                sock.close()
                channel_open = True
            except bluetooth.btcommon.BluetoothError:
                pass


            if channel_open:
                services["open"].append(BluetoothService(BluetoothDevice(interface, address), "RFCOMM", channel))
            else:
                services["closed"].append(BluetoothService(BluetoothDevice(interface, address), "RFCOMM", channel))

        results = (services["open"], services["closed"])
        
        return results
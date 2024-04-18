from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothDevice, BluetoothInterface, BluetoothService
from typing import List
import bluetooth

from autosec.core.ressources.base import AutosecRessource

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [SDPService()]

class SDPService(AutosecModule):
    '''
    Class providing Service Discovery for on a bluetooth device
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="serviceDiscovery",
            description = "Module to scan services on a bluetooth device.",
            dependencies = [],
            tags = ["Bluetooth", "SDP"]
        )
    
    def get_produced_outputs(self) -> List[BluetoothService]:
        return [BluetoothService]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothInterface]
    
    
    def run(self,inputs: List[AutosecRessource]) -> List[BluetoothService]:
        
        interface = self.get_ressource(inputs, BluetoothInterface)
        address = interface.get_bd_addr()
        services = bluetooth.find_service(address=address)
        results = [BluetoothService(BluetoothDevice(interface, interface.get_bd_addr()), service["protocol"], service["port"], service["name"]) for service in services]
        
        return results
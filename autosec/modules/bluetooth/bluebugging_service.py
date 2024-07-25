from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothDevice, BluetoothInterface, BluetoothService, BluetoothConnection, FileData
from typing import List
import subprocess
import time
import bluetooth
import os
from PyOBEX import responses

from autosec.core.ressources.base import AutosecRessource

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [BluebuggingService()]

class BluebuggingService(AutosecModule):
    '''
    Class used to imitate a bluetooth device
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="DeviceImitation",
            description = "Module to imitate a different bluetooth device by using its Bluetooth address and name",
            dependencies = ["Linux", "sudo"],
            tags = ["Bluetooth"]
        )
    
    def get_produced_outputs(self) -> BluetoothConnection:
        return [BluetoothService]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothService]
    
    
    def run(self,inputs: List[AutosecRessource]) -> BluetoothConnection:
        service = self.get_ressource(inputs, BluetoothService)
        if not service.get_protocol() == "RFCOMM":
            print("wrong service was given")
            return False
        socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        socket.connect((service.get_device().get_bd_addr(), service.get_port()))
        cmd = "Test"
        socket.send(cmd)
        
        return 
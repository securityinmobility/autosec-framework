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
    return [BTDeviceImitationService()]

class BTDeviceImitationService(AutosecModule):
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
        return BluetoothDevice, BluetoothInterface
    
    
    def run(self,inputs: List[AutosecRessource]) -> BluetoothConnection:
        interface = self.get_ressource(inputs, BluetoothInterface)
        interface_name = interface.get_interface_name()
        device = self.get_ressource(inputs, BluetoothDevice)
        
        if os.path.isfile("/etc/machine-info"):
            with open("/etc/machine-info", "r") as file:
                lines = file.readlines()
                for line in lines:
                    if line.startswith("PRETTY_HOSTNAME"):
                        name = line

        with open("/etc/machine-info", "w") as file:
            for line in lines:
                if line.startswith("PRETTY_HOSTNAME"):
                    file.write(f"PRETTY_HOSTNAME={device.get_bd_name()}")
                else:
                    file.write(line)
        #subprocess.run(["service", "bluetooth", "restart"])
        ##subprocess.run(["hciconfig", interface_name, "name", old_name])
        subprocess.run(["bdaddr", "-i", interface_name, "-r", device.get_bd_addr()])
        time.sleep(2)
        subprocess.run(["hciconfig", interface_name, "up"])
       
        # connect to a third device

        # reset name and mac
        with open("/etc/machine-info", "w") as file:
            for line in lines:
                if line.startswith("PRETTY_HOSTNAME"):
                    file.write(f"PRETTY_HOSTNAME={name}")
                else:
                    file.write(line)
        
        subprocess.run(["bdaddr", "-i", interface_name, "-r", interface.get_network_address()])
        time.sleep(2)
        subprocess.run(["hciconfig", interface_name, "up"])

        
        return 
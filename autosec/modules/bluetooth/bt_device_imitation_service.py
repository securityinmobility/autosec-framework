from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothDevice, BluetoothInterface, BluetoothService, BluetoothConnection, BTImitationDevice
from typing import List
import subprocess
import time
import bluetooth
import os

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
            tags = ["Bluetooth", "bdaddr"]
        )
    
    def get_produced_outputs(self) -> BluetoothConnection:
        return [BluetoothService]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothDevice, BluetoothInterface, BluetoothService]
    
    
    def run(self,inputs: List[AutosecRessource]) -> BluetoothConnection:
        interface = self.get_ressource(inputs, BluetoothInterface)
        interface_name = interface.get_interface_name()
        device = self.get_ressource(inputs, BluetoothDevice)
        service = self.get_ressource(inputs, BluetoothService)

        print("changing Bluetooth address and name")
        if os.path.isfile("/etc/machine-info"):
            with open("/etc/machine-info", "r") as file:
                lines = file.readlines()
                for line in lines:
                    if line.startswith("PRETTY_HOSTNAME"):
                        name = line.replace("PRETTY_HOSTNAME=", "")

        with open("/etc/machine-info", "w") as file:
            for line in lines:
                if line.startswith("PRETTY_HOSTNAME"):
                    file.write(f"PRETTY_HOSTNAME={device.get_bd_name()}")
                else:
                    file.write(line)

        subprocess.run(["service", "bluetooth", "restart"])
        time.sleep(1)
        ##subprocess.run(["hciconfig", interface_name, "name", old_name])
        subprocess.run(["bdaddr", "-i", interface_name, "-r", device.get_bd_addr()])
        time.sleep(1)
        subprocess.run(["hciconfig", interface_name, "up"])
       
        print("Connecting to service")
        # connect to a third device
        try:
            # Create a Bluetooth socket using RFCOMM
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            sock.connect((service.get_device().get_bd_addr(), service.get_port()))
        except bluetooth.BluetoothError as e:
                print(f"Bluetooth error: {e}")

        finally:
            # Close the socket
            print("Closing connection")
            sock.close()
            
        print(device.get_interface().get_interface_name())
        imitation_device = BTImitationDevice(BluetoothInterface(interface_name, device.get_interface().get_network_address()), device.get_bd_addr(), interface.get_network_address(), device.get_bd_name(), name)

        

        
        return imitation_device
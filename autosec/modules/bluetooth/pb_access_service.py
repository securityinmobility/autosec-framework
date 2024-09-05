from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.bluetooth import BluetoothDevice, BluetoothInterface, BluetoothService, VCard
import autosec.modules.bluetooth.bt_obex as bt_obex
from typing import List
from xml.etree import ElementTree
from PyOBEX import responses

from autosec.core.ressources.base import AutosecRessource

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [PBAccessService()]

class PBAccessService(AutosecModule):
    '''
    Class providing Service Discovery for on a bluetooth device
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="PhonebookAccess",
            description = "Module to get access to the phonebook on a bluetooth device.",
            dependencies = ["PyOBEX"],
            tags = ["Bluetooth", "RFCOMM", "Phonebook", "OBEX"]
        )
    
    def get_produced_outputs(self) -> List[VCard]:
        return [BluetoothService]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [BluetoothService]
    
    
    def run(self,inputs: List[AutosecRessource]) -> List[VCard]:
        
        service = self.get_ressource(inputs, BluetoothService)
        address = service.get_device().get_bd_addr()
        port = service.get_port()
        
        print(f"Trying to connect on port {port}")
        c = bt_obex.PBAPClient(address, port)
        r = c.connect()

        if isinstance(r, responses.ConnectSuccess):
        
            prefix = ""
            hdrs, cards = c.get(prefix+"telecom/pb", header_list=[bt_obex.TypeHeader(b"x-bt/vcard-listing")])
            root = ElementTree.fromstring(cards)
            
            #print("\nAvailable cards in %stelecom/pb\n" % prefix)
            
            names = []
            for card in root.findall("card"):
                names.append(card.attrib["handle"])
            
            #print("\nCards in %stelecom/pb\n" % prefix)
            
            c.setpath(prefix + "telecom/pb")
            
            card_info = []
            for name in names:
                hdrs, card = c.get(name, header_list=[bt_obex.TypeHeader(b"x-bt/vcard")])
                card_str = card.decode().replace(";", "")
                this_card = {}
                this_card["tel"] = []
                this_card["email"] = []

                for line in card_str.split("\n"):
                    line = line.replace("CHARSET=UTF-8", "")
                    #print(f"line: {line}")
                    if line.startswith("VERSION"):
                        this_card["version"] = line.split(":")[1]

                    if line.startswith("N:"):
                        this_card["name"] = line.split(":")[1]

                    if line.startswith("FN:"):
                        this_card["full_name"] = line.split(":")[1]

                    if line.startswith("TEL"):
                        this_card["tel"].append(line.split(":")[1].strip())

                    if line.startswith("EMAIL"):
                        this_card["email"].append(line.split(":")[1].strip())

                    if line.startswith("BDAY"):
                        this_card["bday"] = line.split(":")[1]

                card_info.append(this_card)
                #print(card_str)
            
            c.disconnect()

        else:
            print("Connection could not be established")
            if r.code == 198:
                print("Connection not acceptable")
            elif r.code == 211:
                print("Service not available")
            results = None


        results = []

        for card in card_info:
            #print(card)
            vcard = VCard(float(card["version"]), card["name"], card["full_name"], card["tel"], card["email"], card["bday"] if "bday" in card else None)
            results.append(vcard)
        
        return results
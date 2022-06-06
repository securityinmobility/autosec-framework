from scapy.all import ARP, Ether, srp, in6_isvalid, arping, sr
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.ip import InternetDevice, InternetInterface
from typing import List

from autosec.core.ressources.base import AutosecRessource


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [ArpService()]


class ArpService(AutosecModule):
    '''
    Class that provides ARP scan for a network
    '''

    def __init__(self):
        super().__init__()

        self.ether_broadcast = "ff:ff:ff:ff:ff:ff"

    def get_info(self):
        return AutosecModuleInformation(
            name = "arpScan",
            description = "Module to perform ARP scanning IPs in a network.",
            dependencies = [],
            tags = ["IP","ARP","Scan"]
        )
    
    def get_produced_outputs(self) -> List[InternetDevice]:
        return [InternetDevice]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [InternetInterface]
    
    
    def run(self,inputs: List[AutosecRessource]) -> List[InternetDevice]:
        
        interface = self.get_ressource(inputs, InternetInterface)
       
        arp_request = ARP(pdst=interface.get_network_address())
        broadcast = Ether(dst=self.ether_broadcast)
        arp_request_broadcast = broadcast/arp_request
        answered, _ = srp(arp_request_broadcast, timeout=5) #iface=interface.get_interface_name()
        #ans, _ = arping(interface.get_network_address(), timeout=2)
        addresses  = set(received.psrc for received,_ in answered)
        results = [InternetDevice(input,ipv6=address) if (in6_isvalid(address)) else InternetDevice(input,ipv4=address) for address in addresses]
        
        return results

    
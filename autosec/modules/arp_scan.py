from scapy.all import ARP, Ether, srp, in6_isvalid
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import ip, InternetDevice, InternetInterface
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
        interface = self.get_ressources(inputs, InternetInterface)
        results = []
        for input in interface:
            arp_request = ARP(pdst=input.get_address())
            broadcast = Ether(dst=self.ether_broadcast)
            arp_request_broadcast = broadcast/arp_request
            answered, _ = srp(arp_request_broadcast, timeout=2)
            result = [InternetDevice(ipv6=received.psrc) if (in6_isvalid(received)) else InternetDevice(ipv4=received.psrc)  for received,_ in answered]
            results += result
        return results

    
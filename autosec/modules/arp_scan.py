from scapy.all import ARP, Ether, srp, in6_isvalid
from autosec.core.autosec_module import AutosecModule
from autosec.core.ressources import ip


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [ArpService()]

class ArpService(AutosecModule):

    def __init__(self):
        super().__init__()

        self.ether_broadcast = "ff:ff:ff:ff:ff:ff"

    def get_info(self):
        return (dict(
            name = "arpScan",
            source = "autosec",
            type = "arping",
            interface = "IP",
            description = "Module to perform ARP scanning IPs in a network."
        ))
    
    def get_produced_outputs(self):
        return [ip.InternetDevice]
    

    def get_required_ressources(self):
        return [ip.InternetDevice]
    

    def get_optional_ressources(self):
        return None

    
    def can_run(self, inputs):
        runnable = super().can_run(inputs)
        return runnable

    
    def run(self, inputs):
        results = []
        for input in inputs:
            arp_request = ARP(pdst=input.get_address())
            broadcast = Ether(dst=self.ether_broadcast)
            arp_request_broadcast = broadcast/arp_request
            answered, _ = srp(arp_request_broadcast, timeout=2)
            result = [ip.InternetDevice(ipv6=received.psrc) if (in6_isvalid(received)) else ip.InternetDevice(ipv4=received.psrc)  for received,_ in answered]
            results += result
        return results

    
from scapy.all import IP, TCP, L3RawSocket,sr
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.ip import InternetDevice, InternetService, InternetInterface
from autosec.core.ressources.base import AutosecRessource
from typing import List
import socket


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [PortService()]

class PortService(AutosecModule):
    '''
    Class that provides port scanning for an ip address.
    '''

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name = "portScan",
            description = "Module to perform scanning for open ports for a given network device.",
            dependencies=[],
            tags = ["IP", "Port", "Scan"],
        )
    
    def get_produced_outputs(self) -> List[InternetService]:
        return [InternetService]
    

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [InternetInterface, InternetDevice]
    
    
    def run(self, inputs: List[AutosecRessource]) -> List[InternetService]:
        #conf.L3socket = L3RawSocket
        device = self.get_ressource(inputs, InternetDevice)
        ip_address = device.get_address()
     
        res, uns = sr(IP(dst=ip_address)/TCP(flags="S",dport=(1,80)))
        a = res.filter(lambda s,r: (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)))
        open_ports = [answer.getlayer(TCP).sport for query, answer in a]
        service_name = []
        for port in open_ports:
            try:
                port_service_name = socket.getservbyport(port)
            except:
                port_service_name = "unknown"
            service_name.append(port_service_name)

        return [InternetService(device=device, port=p, service_name=s) for p, s in zip(open_ports, service_name)]

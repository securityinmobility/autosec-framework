from scapy.all import RandShort, conf, sr1, IP, TCP, in6_isvalid, L3RawSocket
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import ip, AutosecRessource, InternetDevice, InternetService, InternetInterface
from typing import List


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
        conf.L3socket = L3RawSocket
        device = self.get_ressource(inputs, InternetDevice)
        ip_address = device.get_address()
        src_port = RandShort()
        open_ports = []
        for port in range(1, 65536):
            ipPkt = IP(dst=ip_address)
            tcpPkt = TCP(sport=src_port, dport=port, flags="S")
            response = sr1(ipPkt/tcpPkt, timeout=15, verbose = 0)
            if response is not None and response.haslayer(TCP):
                if response.getlayer(TCP).flags == "SA":
                    open_ports.append(InternetService(device= device, port=port))
        return open_ports

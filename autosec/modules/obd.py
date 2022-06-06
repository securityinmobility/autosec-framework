'''
Load Obd modules
'''
from scapy.all import OBD, OBD_S09, OBD_S01
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource, CanInterface
from autosec.core.ressources.can import IsoTPService
from autosec.modules.Obd import service01, service09
from autosec.core.ressources.obdInfo import ObdInfo
from typing import List


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [ObdServices()]

class ObdServices(AutosecModule):
    '''
    Class that provides the service01 and service09 functions.
    '''
    def __init__(self):
        super().__init__()


    def get_info(self):
        return AutosecModuleInformation(
            name = "ObdServices",
            description = "Module that interprets OBD-II service 01 and 09 PIDs",
            tags = ["Obd", "CAN", "service", "payload"])


    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [ObdInfo]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface, IsoTPService]


    def run(self, inputs: List[AutosecRessource]) -> List[ObdInfo]:
        isoTpSocket = self.get_ressource(inputs, [IsoTPService]).get_socket()

        results = []

        # service 9, request vin
        req_9 = OBD()/OBD_S09(iid=[0x02])
        resp_9 = isoTpSocket.sr1(req_9)  # -> show() 
        dump_9 = resp_9.show(dump=True)
        results.add(ObdInfo(dump_9, 9, 0x02))

        # service 1
        pid_list = [0x00, 0x21, 0x1C, 0x0D, 0x0C, 0x05, 0x04, 0x03, 0x01]
        """ 
        0x00: get supported pid
        0x21: Distance traveled with malfunction indicator lamp (MIL) on
        0x1C: OBD standards this vehicle conforms to
        0x0D: Vehicle speed 
        0x0C: Engine speed
        0x05: Engine coolant temperature
        0x04: Calculated engine load 
        0x03: Fuel system status
        0x01:  Monitor status since DTCs cleared. (Includes malfunction indicator lamp (MIL)
        """

        for pId in pid_list:
            req = OBD()/OBD_S01(pid=[pId])
            resp = isoTpSocket.sr1(req)
            dump = resp.show(dump=True)
            results.add(ObdInfo(dump, 1, pId))

        return results

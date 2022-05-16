'''
Load Obd modules
'''
from scapy.all import OBD, OBD_S09, OBD_S01
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource, CanInterface
from autosec.core.ressources.can import IsoTPService
from autosec.modules.Obd import service01, service09
from autosec.modules.Obd.obdInfo import ObdInfo
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

    """
        self.functions = {
            0x01: service01.get_mil_status,
            0x03: service01.get_fuelsystem_status,
            0x04: service01.get_engine_load,
            0x05: service01.get_engine_coolant_temp,
            0x0C: service01.get_engine_speed,
            0x0D: service01.get_vehicle_speed,
            0x1C: service01.get_obd_standard,
            0x21: service01.get_distance_with_mil,
        }

        self.info_dict = {}
        self.raw_data = {}
    """

    def get_info(self):
        return AutosecModuleInformation(
            name = "ObdServices",
            description = "Module that interprets OBD-II service 01 and 09 PIDs",
            tags = ["Obd", "CAN", "service", "payload"])


    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [ObdInfo]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface, IsoTPService]

    """
    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:

        interface = self.get_ressource(inputs, [CanInterface])

        vin_results = service09.get_vin(interface)
        self.info_dict = {}
        self.raw_data = {}
        if vin_results:
            self.info_dict.update(vin_results[0])
            self.raw_data.update(vin_results[1])

        for pid, function in self.functions.items():
            func_info = function(interface, pid)
            if func_info:
                self.info_dict.update(func_info[0])
                self.raw_data.update(func_info[1])

        return [ObdInfo(self.info_dict, self.raw_data)]
    """

    def run(self, inputs: List[AutosecRessource]) -> List[ObdInfo]:
        isoTpSocket = self.get_ressource(inputs, [IsoTPService]).get_socket()

        results = []

        # service 9, request vin
        req_9 = OBD()/OBD_S09(iid=[0x02])
        resp_9 = isoTpSocket.sr1(req_9)  # -> show() 
        dump_9 = resp_9.show(dump=True)
        results.add(dump_9)
        # service 1

        req_00 = OBD()/OBD_S01(pid=[0x00])  # get supported pid
        resp_00 = isoTpSocket.sr1(req_00)
        dump_00 = resp_00.show(dump=True)

        req_21 = OBD()/OBD_S01(pid=[0x21])  # Distance traveled with malfunction indicator lamp (MIL) on 
        resp_21 = isoTpSocket.sr1(req_21)
        dump_21 = resp_21.show(dump=True)
        results.add(dump_21)

        req_1C = OBD()/OBD_S01(pid=[0x1C])  # OBD standards this vehicle conforms to
        resp_1C = isoTpSocket.sr1(req_1C)
        dump_1C = resp_1C.show(dump=True)
        results.add(dump_1C)

        req_0D = OBD()/OBD_S01(pid=[0x0D])  # Vehicle speed 
        resp_0D = isoTpSocket.sr1(req_0D)
        dump_0D = resp_0D.show(dump=True)
        results.add(dump_0D)

        req_0C = OBD()/OBD_S01(pid=[0x0C])  # Engine speed 
        resp_0C = isoTpSocket.sr1(req_0C)
        dump_0C = resp_0C.show(dump=True)
        results.add(dump_0C)

        req_05 = OBD()/OBD_S01(pid=[0x05])  # Engine coolant temperature
        resp_05 = isoTpSocket.sr1(req_05)
        dump_05 = resp_05.show(dump=True)
        results.add(dump_05)

        req_04 = OBD()/OBD_S01(pid=[0x04])  # Calculated engine load 
        resp_04 = isoTpSocket.sr1(req_04)
        dump_04 = resp_04.show(dump=True)
        results.add(dump_04)

        req_03 = OBD()/OBD_S01(pid=[0x03])  # Fuel system status
        resp_03 = isoTpSocket.sr1(req_03)
        dump_03 = resp_03.show(dump=True)
        results.add(dump_03)

        req_01 = OBD()/OBD_S01(pid=[0x01])  # Monitor status since DTCs cleared. (Includes malfunction indicator lamp (MIL)
        resp_01 = isoTpSocket.sr1(req_01)
        dump_01 = resp_01.show(dump=True)
        results.add(dump_01)

        return results

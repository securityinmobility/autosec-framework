'''
Load Obd modules
'''

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

    def get_info(self):
        return AutosecModuleInformation(
            name = "ObdServices",
            description = "Module that interprets OBD-II service 01 and 09 PIDs",
            tags = ["Obd", "CAN", "service", "payload"])


    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [ObdInfo]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface]


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

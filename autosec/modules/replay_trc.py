
import sys 
sys.path.append("../autosec-framework-module-automation")

from autosec.core.ressources.trc import TRCData
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.base import AutosecRessource
from autosec.core.ressources.can import CanInterface
from typing import List
import time
from scapy.all import *



def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [TrcService()]

class TrcService(AutosecModule):
    """
    #Class that provides replaying of trc files
    """

    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name="trcReplay",
            description="Module to perform replaying of trc files.",
            dependencies=[],
            tags=["TRC", "Replay"]
        )
    
    def get_produced_outputs(self) -> List[AutosecRessource]:
        return []

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface, TRCData]
    
    def run(self, inputs: List[AutosecRessource]):
        trc = self.get_ressource(inputs, TRCData)
        interface = self.get_ressource(inputs, CanInterface)

        trc_data = trc.get_data()
        t = 0
        for d in trc_data:
            time_offset = d.get("time offset")
            data = d.get("data [hex]")
            print(data, len(data))
            msg_id = int(d.get("message number"))
            print(type(data))
            time.sleep(time_offset-t)
            interface.send_message(msg_id=msg_id, data=data)
            #interface.send(CAN(identifier))

            t = time_offset

        return []



'''
Load Obd modules
'''
from autosec.core.autosec_module import AutosecModule
from autosec.modules.Obd import service01


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [ObdService01()]

class ObdService01(AutosecModule):
    '''
    Class that provides the service01 functions.
    '''
    def __init__(self):
        self.interface = "vcan0"

    def get_info(self):
        return(dict(
            name = "obdService01",
            source = "autosec",
            type = "payload",
            interface = "CAN",
            description = "Module that interprets OBD-II service 01 PIDs"))

    def get_options(self):
        pass

    def set_options(self, options):
        pass

    def run(self):
        # TODO: Check for available PIDs, then run the matching functions.
        for func in dir(service01):
            function = getattr(service01,func)
            if callable(function) and func.startswith("get") and not func == "get_supported_pid":
                function(self.interface)
        pids = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0]
        for pid in pids:
            service01.get_supported_pid(self.interface, pid)
        
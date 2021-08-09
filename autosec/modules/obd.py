'''
Load Obd modules
'''
import logging
from autosec.core.autosec_module import AutosecModule
from autosec.modules.Obd import service01, service09, isotp_endpoints


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [ObdServices(), IsoTpServices()]

class ObdServices(AutosecModule):
    '''
    Class that provides the service01 and service09 functions.
    '''
    def __init__(self):
        self.logger = logging.getLogger("autosec.modules.obd")
        self.logger.setLevel(logging.WARNING)

        self.interface = "vcan0"

        self.functions = {
            "01": service01.get_mil_status,
            "03": service01.get_fuelsystem_status,
            "04": service01.get_engine_load,
            "05": service01.get_engine_coolant_temp,
            "0C": service01.get_engine_speed,
            "0D": service01.get_vehicle_speed,
            "1C": service01.get_obd_standard
        }

    def get_info(self):
        return(dict(
            name = "ObdServices",
            source = "autosec",
            type = "payload",
            interface = "CAN",
            description = "Module that interprets OBD-II service 01 and 09 PIDs"))

    def get_options(self):
        return dict(
            interface = dict(name = "interface",
                required = True,
                default = "vcan0",
                unit = "SocketCAN Device Name",
                range = None,
                value = self.interface),
            )

    def set_options(self, options):
        self.interface = options

    def run(self):
        service09.get_vin()
        self.check_pid_and_run()

    def check_pid_and_run(self):
        pids = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0]
        for pid in pids:
            pid_list = service01.get_supported_pid(self.interface, pid)
            if pid_list is None:
                self.logger.warning(f"No list returned for PID {hex(pid)}")
            else:
                for available_pid in pid_list:
                    if available_pid in self.functions:
                        self.functions[available_pid](self.interface)

class IsoTpServices(AutosecModule):
    '''
    Class that provides the isotp endpoints scan.
    '''
    def __init__(self):
        self.logger = logging.getLogger("autosec.modules.obd")
        self.logger.setLevel(logging.WARNING)

        self.interface = "vcan0"

    def get_info(self):
        return(dict(
            name = "ObdService01",
            source = "autosec",
            type = "payload",
            interface = "CAN",
            description = "Module that interprets OBD-II service 01 PIDs"))

    def get_options(self):
        return dict(
            interface = dict(name = "interface",
                required = True,
                default = "vcan0",
                unit = "SocketCAN Device Name",
                range = None,
                value = self.interface),
            )

    def set_options(self, options):
        self.interface = options

    def run(self):
        isotp_endpoints.scan_endpoints(self.interface)

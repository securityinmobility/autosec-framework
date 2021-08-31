'''
Load Obd modules
'''
from autosec.core.autosec_module import AutosecModule
from autosec.modules.Obd import service01, service09


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

        #self.logger = logging.getLogger("autosec.modules.obd")
        #self.logger.setLevel(logging.WARNING)

        self._add_option("interface",
            description="Interface for the ObdServices",
            required=True)

        self._add_option("checkPID",
            description="Run a check for available ECU PIDs and runs the corresponding functions",
            required=False,
            default=True,
            value=True)

        self.interface = None
        self.check_pids = True

        self.functions = {
            0x01: service01.get_mil_status,
            0x03: service01.get_fuelsystem_status,
            0x04: service01.get_engine_load,
            0x05: service01.get_engine_coolant_temp,
            0x0C: service01.get_engine_speed,
            0x0D: service01.get_vehicle_speed,
            0x1C: service01.get_obd_standard
        }

        self.info_dict = {}
        self.raw_data = {}

    def get_info(self):
        return(dict(
            name = "ObdServices",
            source = "autosec",
            type = "payload",
            interface = "CAN",
            description = "Module that interprets OBD-II service 01 and 09 PIDs"))

    def run(self):
        try:
            super().run()
        except ValueError as error:
            self.logger.warning(error)
            return error

        self.interface = self._options["interface"]["value"]
        self.check_pids = self._options["checkPID"]["value"]

        vin_results = service09.get_vin(self.interface)
        self.info_dict = {}
        self.raw_data = {}
        self.info_dict.update(vin_results[0])
        self.raw_data.update(vin_results[1])

        if self.check_pids is True:
            self.info_dict = self._check_pid_and_run()
            return self.info_dict

        self.logger.warning("Running all functions, not checking for ECU PIDs")
        for pid, function in self.functions.items():
            func_info = function(self.interface, pid)
            self.info_dict.update(func_info[0])
            self.raw_data.update(func_info[1])
        return self.info_dict, self.raw_data

    def _check_pid_and_run(self):
        pids = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0]
        for pid in pids:
            pid_list = service01.get_supported_pid(self.interface, pid)
            self.raw_data.update(pid_list[1])
            self.logger.warning(self.raw_data)
            if pid_list[0] is None:
                self.logger.warning(f"No list returned for PID 0x{pid:02X}")
            else:
                for available_pid in pid_list[0]:
                    if available_pid in self.functions:
                        func_info = self.functions[available_pid](self.interface, available_pid)
                        self.info_dict.update(func_info[0])
                        self.raw_data.update(func_info[1])
        return self.info_dict, self.raw_data

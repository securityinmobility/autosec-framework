'''
Load Obd modules
'''
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
            return

        self.interface = self._options["interface"]["value"]
        self.check_pids = self._options["checkPID"]["value"]

        service09.get_vin(self.interface)

        if self.check_pids is True:
            self._check_pid_and_run()
        else:
            self.logger.warning("Running all functions, not checking for ECU PIDs")
            for function in self.functions.values():
                function(self.interface)

    def _check_pid_and_run(self):
        pids = [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0]
        for pid in pids:
            pid_list = service01.get_supported_pid(self.interface, pid)
            if pid_list is None:
                self.logger.warning(f"No list returned for PID 0x{pid:02X}")
            else:
                for available_pid in pid_list:
                    if available_pid in self.functions:
                        self.functions[available_pid](self.interface, available_pid)

class IsoTpServices(AutosecModule):
    '''
    Class that provides the isotp endpoints scan.
    '''
    def __init__(self):
        super().__init__()

        #self.logger = logging.getLogger("autosec.modules.obd")
        #self.logger.setLevel(logging.WARNING)

        self._add_option("interface",
            description="Interface for the ObdServices",
            required=True)

        self._add_option("scanType",
            description="Scan Type for normal, extended or both",
            required=False)

        self._add_option("scanRange",
            description="Set scan range",
            required=True)

        self._add_option("extendedRange",
            description="Set scan range for extended IDs",
            required=False)

        self.interface = None
        self.scan_type = None
        self.scan_range = None
        self.extended_range = None

    def get_info(self):
        return(dict(
            name = "IsoTpServices",
            source = "autosec",
            type = "payload",
            interface = "CAN",
            description = "Module that interprets services that run over ISO-TP"))

    def run(self):
        try:
            super().run()
        except ValueError as error:
            self.logger.warning(error)
            return

        self.interface = self._options["interface"]["value"]
        self.scan_type = self._options["scanType"]["value"]
        # example: range(0x700,0x7ff), ext: range(0x40,0x5a)
        self.scan_range = self._options["scanRange"]["value"]
        self.extended_range = self._options["extendedRange"]["value"]

        isotp_endpoints.scan_endpoints(self.interface, self.scan_type,
                                       self.scan_range, self.extended_range)

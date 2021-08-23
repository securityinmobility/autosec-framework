'''
Load ISO TP modules
'''
from autosec.core.autosec_module import AutosecModule
from autosec.modules.Obd import isotp_endpoints


def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [IsoTpServices()]

class IsoTpServices(AutosecModule):
    '''
    Class that provides the isotp endpoints scan.
    '''
    def __init__(self):
        super().__init__()

        #self.logger = logging.getLogger("autosec.modules.obd")
        #self.logger.setLevel(logging.WARNING)

        self._add_option("interface",
            description="Interface for the IsoTpServices",
            required=True)

        self._add_option("scanType",
            description="Scan Type for normal, extended or both",
            required=False,
            default="both",
            value="both")

        self._add_option("scanRange",
            description="Set scan range",
            required=True)

        self._add_option("extendedRange",
            description="Set scan range for extended IDs, required if scanType is extended or both",
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
            description = "Module that interprets services that run over ISO TP"))

    def run(self):
        if (self._options["scanType"]["value"] == "extended" or
                self._options["scanType"]["value"] == "both"):
            self._options["extendedRange"]["required"] = True
        else:
            self._options["extendedRange"]["required"] = False

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

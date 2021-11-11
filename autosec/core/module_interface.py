'''
This is the basic interface that has to be implemented by all adapters that
introduce modules to the autosec framework

For MSF a special loader will be needed that creates the different instances
of the modules itself.
'''
import logging

class ModuleInterface():
    '''
    Interface for the modules
    '''
    def __init__(self):
        '''
        Initialize the module
        '''
<<<<<<< HEAD
        self.log = Logger()
        self.options = {}
=======
        self._module_name = str(self._class__).split(".")[-1][:-2]
        self.logger = logging.getLogger(f"autosec.modules.{self._module_name}")
        self._options = dict()
>>>>>>> feature/can_bridge

    def get_info(self):
        '''
        This method returns information about the module, e.g. name, package / type,
        interface, purpose etc.

        @return: information as dictionary with the following keys:
        name
        source (e.g. msf, autosec, etc.)
        type (e.g. sniffer, scanner, exploit, payload, attack ...)
        interface (e.g. ethernet, CAN, LIN, Flexray ...)
        description (textual description)
        '''
        raise NotImplementedError

    def get_options(self):
        '''
        return the specific options this module has with a description

        @return: specific options as list of dictionaries with the following keys:
        name (name or ID of the option)
        required (flag if the option is required or not)
        default (default value if available)
        unit (unit of the option)
        range
        description
        value (value that is currently set if so)
        '''
        return self._options.copy()
        raise NotImplementedError

    def set_options(self, *options):
        '''
        Method to store options for this module. The Options are given within a list of
        tuples with the name and the value.
        TBD: check Range and value of the option (if these requirements are available)
        '''
        for i, op in enumerate(options):
            if len(op) != 2:
                self.logger.warning(f"Could not insert option {op} due to wrong format")
                continue
            key = op[0]
            value = op[1]
            try:
                self._options[key]["value"] = value
            except Exception as e:
                self.logger.warning(f"Could not insert option with key {key}. Value was {value}")

    def run(self):
        '''
        run the module
        '''
        raise NotImplementedError

    def _add_option(self, name, description = "", required = False, default = None):
        '''
        Adds an option to the _options dictionary
        By using this structure, the set_options method can be used
        '''
        self._options[name] = dict(required = required, 
            description = description,
            default = default,
            value = default)

    @classmethod
    def get_can_interfaces(cls):
        '''
        get the accessible CAN interfaces on the current machine
        '''
        with open("/proc/net/dev", 'r', encoding='ascii') as net_device_file:
            net_device_file_lines = net_device_file.readlines()[2:]

        can_device_lines = [x for x in net_device_file_lines if "can" in x]
        can_devices = [x.split(":")[0].strip() for x in can_device_lines]

        return can_devices

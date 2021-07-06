'''
This is the basic interface that has to be implemented by all adapters that
introduce modules to the autosec framework

For MSF a special loader will be needed that creates the different instances
of the modules itself.
'''
from .log import Logger

class ModuleInterface():
    '''
    Interface for the modules
    '''
    def __init__(self):
        '''
        Initialize the module
        '''
        self.log = Logger()
        self.options = dict()

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
        raise NotImplementedError

    def set_options(self, options):
        '''
        Method to store options for this module. The Options are given within a list of
        tuples with the name and the value.
        TBD: check Range and value of the option (if these requirements are available)
        '''

        for option in options:
            try:
                self.options[option[0]] = option[1]
            except ValueError:
                print(f"Error assigning option{option[0]} to module {self.get_info['name']}")

    def run(self):
        '''
        run the module
        '''
        raise NotImplementedError

    @classmethod
    def get_can_interfaces(cls):
        '''
        get the accessible CAN interfaces on the current machine
        '''
        with open("/proc/net/dev", 'r') as net_device_file:
            net_device_file_lines = net_device_file.readlines()[2:]

        can_device_lines = [x for x in net_device_file_lines if "can" in x]
        can_devices = [x.split(":")[0].strip() for x in can_device_lines]

        return can_devices

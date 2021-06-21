from log import Logger


'''
This is the basic interface that has to be implemented by all adapters that introduce modules to the autosec framework

For MSF a special loader will be needed that creates the different instances of the modules itself.
'''

class moduleInterface():
    def __init__(self):
        self.log = Logger()

    def getInfo(self):
        '''
        This method returns information about the module, e.g. name, package / type, interface, purpose etc.

        @return: information as dictionary with the following keys:
        name
        source (e.g. msf, autosec, etc.)
        type (e.g. sniffer, scanner, exploit, payload, attack ...)
        interface (e.g. ethernet, CAN, LIN, Flexray ...)
        description (textual description)
        '''
        raise NotImplementedError

    def getOptions(self):
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

    def setOptions(self, options):
        '''
        Method to store options for this module. The Options are given within a list of tuples with the name and the value.
        TBD: check Range and value of the option (if these requirements are available)
        '''

        for op in options:
            try:
                self.options[op[0]] = op[1]
            except ValueError:
                print(f"Error assigning option{op[0]} to module {self.getInfo['name']}")
    

    def run(self):
        raise NotImplementedError

    def getCanInterfaces(self):
        netDeviceFile = open("/proc/net/dev", 'r')
        netDeviceFileLines = netDeviceFile.readlines()[2:]
        netDeviceFile.close()

        canDeviceLines = [x for x in netDeviceFileLines if "can" in x]
        canDevices = [x.split(":")[0].strip() for x in canDeviceLines]

        return canDevices
        


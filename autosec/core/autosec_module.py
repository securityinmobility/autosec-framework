'''
This is the basic interface that has to be implemented by all adapters that introduce
modules to the autosec framework. This module also introduces some functionality, that
may help to create modules faster.
'''
import logging
from typing import TypedDict

class AutosecModuleInformation(TypedDict):
    name: str
    source: str
    type: str
    interface: str
    description: str

class AutosecModule():
    '''
    Class the modules should inherit from
    '''

    def __init__(self):
        '''
        Initialize the module, create logger and empty options dictionary
        '''
        self._module_name = str(self.__class__).split(".")[-1][:-2]
        self.logger = logging.getLogger(f"autosec.modules.{self._module_name}")
        self._options = dict()

    def get_info(self) -> AutosecModuleInformation:
        '''
        This method returns information about the module, e.g. name, package / type, interface,
        purpose etc.

        @return: information as dictionary with the following keys:
        name
        source (e.g. msf, autosec, etc.)
        type (e.g. sniffer, scanner, exploit, payload, attack ...)
        interface (e.g. ethernet, CAN, LIN, Flexray ...)
        description (textual description)
        '''
        raise NotImplementedError

    def get_options(self) -> dict:
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

    def set_options(self, *options):
        '''
        Method to store options for this module. The Options are given within a list of
        tuples with the name and the value.
        TBD: check Range and value of the option (if these requirements are available)
        '''

        for option in options:
            if len(option) != 2:
                self.logger.warning(f"Could not insert option {option} due to wrong format")
                continue
            key = option[0]
            value = option[1]
            try:
                self._options[key]["value"] = value
            except KeyError:
                self.logger.warning(f"Could not insert option with key {key}. Value was {value}")

    def run(self):
        '''
        Method to run the module.
        '''
        for key in self._options:
            if self._options[key]["value"] is None and self._options[key]["default"] is not None:
                self._options[key]["value"] = self._options[key]["default"]
            if  self._options[key]["required"] and self._options[key]["value"] == None:
                raise ValueError(f"Required option {key} is not set")

    def _add_option(self, name: str, description: str = "", required: bool = False, default = None, value = None):
        '''
        Adds an option to the _options dictionary
        By using this structure, the set_options method can be used
        '''
        self._options[name] = dict(description = description,
            required = required,
            default = default,
            value = value)

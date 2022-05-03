'''
This is the basic interface that has to be implemented by all adapters that introduce
modules to the autosec framework. This module also introduces some functionality, that
may help to create modules faster.
'''
import logging
from typing import TypedDict, List, Union
from abc import ABC, abstractmethod
from ressources.base import AutosecRessource

class AutosecModuleInformation(TypedDict):
    '''
    Typed dictionary holding meta information about an autosec module
    '''

    '''
    name of the module
    '''
    name: str

    '''
    description of the module
    '''
    description: str

    '''
    list of (python-)modules this module is based on
    '''
    dependencies: List[str]

    '''
    list with tags for identifying the actions of this module
    e.g. "CAN", "TCP", "CVE", "hash", "scan", ...
    '''
    tags: List[str]

class AutosecExpectedMetrics(TypedDict):
    '''
    Typed dictionary holding information wether meta information about
    possibility, complexity and success expectance of an attack given specific
    ressources as input
    '''

    '''
    Wether it is possible to run the attack with the given ressources
    '''
    can_run: bool

    '''
    Expected runtime of the attack in seconds.
    The actual runtime can depend on numerous factors. This is merely a guess
    based on the given ressources 
    '''
    expected_runtime: float

    '''
    Expected chance for the attack to succeed.
    Floating point number between 0 and 1
    '''
    expected_success: float



class AutosecModule(ABC):
    '''
    Class all modules of the framework should inherit from
    '''

    def __init__(self):
        '''
        Initialize the module, create logger and empty options dictionary
        '''
        self._module_name = str(self.__class__).rsplit(".", maxsplit=1)[:-2]
        self.logger = logging.getLogger(f"autosec.modules.{self._module_name}")

    @abstractmethod
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

    @abstractmethod
    def get_produced_outputs(self) -> List[AutosecRessource]:
        '''
        return the list of potentially produced outputs
        '''
        raise NotImplementedError

    @abstractmethod
    def get_required_ressources(self) -> List[AutosecRessource]:
        '''
        return the minimal ressources required to run this attack
        '''
        raise NotImplementedError

    def get_optional_ressources(self) -> List[AutosecRessource]:
        '''
        returns a list of optional ressources, which, when given might improve
        performance or increase the success rate
        '''
        return []

    def can_run(self, inputs: List[AutosecRessource]) -> Union[bool, AutosecExpectedMetrics]:
        '''
        This method returns expected metrics of running the attack with the
        given 

        @return: a boolean wether the attack is possible or detailed
        information about expected runtime and success rate
        '''
        for req in self.get_required_ressources():
            given_amount = len([x for x in inputs if isinstance(x, req)])
            required_amount = len([x for x in required if x == req])
            if given_amount < required_amount:
                return False

        return True

    @abstractmethod
    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        '''
        Method to perform the attack.
        '''
        raise NotImplementedError

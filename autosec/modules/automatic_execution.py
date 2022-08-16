from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core import load_modules
from autosec.core.ressources import AutosecRessource
from typing import List



def load_module():
    """
    Method to provide the module to the framework
    """
    return [AutomaticExecution()]


class AutomaticExecution(AutosecModule):

    _internet_device_lst = None
    _internet_service_lst = None
    _can_device_lst = None
    _can_service_lst = None
    _isotpService_lst = None
    _can_interface = None
    _internet_interface = None


    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name = "automaticExecution",
            description = "Module to automatically test all possible ressources",
            dependencies = [],
            tags = ["automatic"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [AutosecRessource]
    

    def get_required_ressources(self):
        return []


    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        ressources_lst = inputs
        modules = load_modules.load_all_modules()
        end = False
        while not end:
            found_new = False
            # check which modules are available
            available_modules = [module for module in modules if module.can_run(ressources_lst)]
            for module in available_modules:
                results = module.run(ressources_lst)
                # check if found ressources are new
                if results:
                    for result in results:
                        # check if ressources are the same class
                        ressources_to_check = [result.__eq__(ressource) for ressource in ressources_lst if type(result) == type(ressource)]
        
                        if not ressources_to_check:
                            ressources_lst.append(result)
                            found_new = True

                        elif not any(ressources_to_check) and len(ressources_to_check) > 0:
                            ressources_lst.append(result)
                            found_new = True
            # stopp if no new ressources where found
            if not found_new:
                end = True

        return ressources_lst
'''
This modules provides methods to load the available modules and
therefore to implement the plugin-structure
'''

import importlib
import os
import sys
from .log import Logger

def load_available_modules():
    '''
    Loads all available modules in the modules folder'''
    module_list = []
    modules_path = os.path.join(os.path.dirname(__file__), "..", "modules")
    #Make this better by directly referring from the main dir?
    sys.path.append(modules_path)
    file_list = os.listdir(modules_path)
    modules_list = [file[:-3] for file in file_list if file.endswith(".py")
        and not file == "__init__.py"]
    modules = [importlib.import_module(module, "modules") for module in modules_list]
    for module in modules:
        try:
            module_list.append(module.load_module())
        except AttributeError as error:
            Logger.getInstance.warning(
                f"Module {module} was not loaded due to missing load_module() function")
        except error:
            Logger.getInstance.f(f"Module {module} was not loaded due to an unknown error:")
            Logger.getInstance.f(error)

    return module_list

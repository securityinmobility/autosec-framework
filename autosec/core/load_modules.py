
import sys
sys.path.append("../autosec-framework-master")


from inspect import getmembers, isfunction
from autosec.core.autosec_module import AutosecModule
from autosec.modules import *
import importlib, pathlib
import sys, os 


def load_all_modules():
    parent_path = pathlib.Path(__file__).parent.parent
    path = pathlib.Path.joinpath(parent_path,'modules')
    file_list = os.listdir(path)
    modules_list = [file for file in file_list
                    if file.endswith(".py")
                    and not file == "__init__.py"
                    and not file == "test_module_interfaces.py"
                    and not file == "obd.py"
                    and not file == "replay_trc.py"
                    and not file == "automatic_execution.py"
                    and not file == "can_bridge.py"]
   
   
    result = []
    for m in range(len(modules_list)):
        module_path = str(pathlib.Path.joinpath(path, modules_list[m]))
        loader = importlib.machinery.SourceFileLoader(str(modules_list[m]), module_path)
        spec = importlib.util.spec_from_file_location(str(modules_list[m]), module_path, loader=loader)
        mymodule = importlib.util.module_from_spec( spec )
        loader.exec_module( mymodule )
        tmp = mymodule.load_module()[0]
        result.append(tmp)
 
    return result
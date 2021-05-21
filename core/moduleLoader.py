import importlib, os, sys
from .log import Logger

def loadAvailableModules():
    moduleList = []
    modulesPath = os.path.join(os.path.dirname(__file__), "..", "modules")  #Make this better by directly referring from the main dir?
    sys.path.append(modulesPath)
    fileList = os.listdir(modulesPath)
    modulesList = [file[:-3] for file in fileList if file.endswith(".py") and not file == "__init__.py"]
    modules = [importlib.import_module(module, "modules") for module in modulesList]
    for module in modules:
        try:
            moduleList.append(module.load_module())
        except AttributeError as e:
            Logger.getInstance.w(f"Module {module} was not loaded due to missing load_module() function")
        except e:
            Logger.getInstance.f(f"Module {module} was not loaded due to an unknown error:")
            Logger.getInstance.f(e)
    
    return moduleList


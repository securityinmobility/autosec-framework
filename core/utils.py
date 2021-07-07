'''
Module with helping functions to organize necessary tasks
'''
import logging
import importlib
import os
import pathlib
import sys

def set_top_log_level(level="DEBUG"):

    log_level=getattr(logging, level.upper(), logging.DEBUG)
    logfile_dir= os.path.join(os.path.dirname(__file__), 
        "..", "logfiles")
    pathlib.Path(logfile_dir).mkdir(parents=True, exist_ok=True)
    logfile_path = os.path.joing(logfile_dir, "autosec.log")
    
    ##Initialize Logging##
    top_logger = logging.getLogger("autosec")
    #Create handlers for file & stderr that print every
    #message that reaches the top_logger
    logging_handler_stream = logging.StreamHandler()
    logging_handler_stream.setLevel(log_level)
    logging_handler_file = logging.FileHandler(
        logfile_path, 
        mode="a")
    logging_handler_file.setLevel(log_level)
    logging_formatter = logging.Formatter('%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s')
    logging_handler_stream.setFormatter(logging_formatter)
    logging_handler_file.setFormatter(logging_formatter)
    top_logger.addHandler(logging_handler_file)
    top_logger.addHandler(logging_handler_stream)

def load_available_modules():
    '''
    Loads all available modules in the modules folder
    '''

    logger = logging.getLogger("autosec.core.utils")
    logger.setLevel(logging.WARNING)

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
            logger.warning(
                f"Module {module} was not loaded due to missing load_module() function")
        except error:
            logger.exception(f"Module {module} was not loaded due to an unknown error:")
    return module_list

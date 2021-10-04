'''
Module with helping functions to organize necessary tasks
'''
import logging
import importlib
import os
import pathlib
import sys

def set_top_log_level(level="DEBUG"):
    '''
    (Re-)initialize logging using the given log level.
    '''

    log_level = getattr(logging, level.upper(), logging.DEBUG)
    logfile_dir = os.path.join(os.path.dirname(__file__),
        "..", "logfiles")
    pathlib.Path(logfile_dir).mkdir(parents=True, exist_ok=True)
    logfile_path = os.path.join(logfile_dir, "autosec.log")

    ##Initialize Logging##
    top_logger = logging.getLogger("autosec")
    ##Remove all current handlers##
    for handler in top_logger.handlers.copy():
        top_logger.removeHandler(handler)
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

def load_available_modules(ignore_modules = None):
    '''
    Loads all available modules in the modules folder.
    The modules that are named in the "ignore_modules" list are not loaded.
    '''

    ignore_modules = ignore_modules or []

    logger = logging.getLogger("autosec.core.utils")
    logger.setLevel(logging.WARNING)

    modules_path = _add_module_path()
    file_list = os.listdir(modules_path)
    name_list = [file[:-3] for file in file_list if file.endswith(".py")
        and not file == "__init__.py"
        and not file.startswith("test")
        and not file[:-3] in ignore_modules]

    module_list = []
    for module_name in name_list:
        module = importlib.import_module(module_name, "modules")
        print(module)
        if not hasattr(module, "load_module"):
            logger.warning("Module %s ignored due to missing load_module() function",
                module_name)
            continue

        try:
            module_list.append(module.load_module())
        except Exception: # pylint: disable=broad-except
            logger.exception(
                "Module %s was not loaded due to an error during loading",
                    module_name)
    return module_list


def load_module(module_name):
    '''
    Load a single module using the given module name.
    '''

    logger = logging.getLogger("autosec.core.utils")
    logger.setLevel(logging.WARNING)
    _add_module_path()

    py_module = importlib.import_module(module_name, "modules")
    if not hasattr(py_module, "load_module"):
        logger.warning("Module %s ignored due to missing load_module() function",
            module_name)
        return None

    try:
        return py_module.load_module()
    except Exception: # pylint: disable=broad-except
        logger.exception("Module %s was not loaded due to an error during loading",
            module_name)
        return None

def _add_module_path():
    modules_path = os.path.join(os.path.dirname(__file__), "..", "modules")
    #Make this better by directly referring from the main dir?
    sys.path.append(modules_path)
    return modules_path

'''This module implements tests that ensure that the autosec-modules can be loaded correctly'''

from inspect import getmembers, isfunction
from autosec.core.autosec_module import AutosecModule
import sys
import os
import importlib
import pytest

def load_all_modules():
    sys.path.append(os.path.dirname(__file__))
    file_list = os.listdir(os.path.dirname(__file__))
    modules_list = [file[:-3] for file in file_list
                    if file.endswith(".py")
                    and not file == "__init__.py"
                    and not file == "test_module_interfaces.py"]
    return [importlib.import_module(module, "modules") for module in modules_list]

def test_load_modules():
    '''Test to check if every python module in this folder implements the load_module-method'''
    modules = load_all_modules()
    attribute_error_list = []
    for module in modules:
        assert hasattr(module, "load_module")
        assert callable(module.load_module)

def test_module_interface():
    '''
    Test the received modules if they implement the necessary methods defined in the
    autosec_module.py module
    '''
    modules = load_all_modules()
    for module in modules:
        for instance in module.load_module():
            assert isinstance(instance, AutosecModule)
            assert callable(instance.get_info)
            assert callable(instance.get_options)
            assert callable(instance.set_options)
            assert callable(instance.run)

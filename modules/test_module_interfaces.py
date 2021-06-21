'''This module implements tests that ensure that the autosec-modules can be loaded correctly'''

from inspect import getmembers, isfunction
import sys
import os
import importlib
import pytest


def test_load_modules():
    '''Test to check if every python module in this folder implements the load_module-method'''
    sys.path.append(os.path.dirname(__file__))
    file_list = os.listdir(os.path.dirname(__file__))
    modules_list = [file[:-3] for file in file_list
                    if file.endswith(".py")
                    and not file == "__init__.py"
                    and not file == "test_module_interfaces.py"]
    modules = [importlib.import_module(module, "modules") for module in modules_list]
    attribute_error_list = []
    for module in modules:
        if not [x for x in getmembers(module, isfunction) if x[0] == "load_module"]:
            attribute_error_list.append(module)
    if attribute_error_list:
        pytest.fail(
            f"Following modules did not implement the load_module()-Method: {attribute_error_list}")

def test_module_interface():
    '''Test the received modules if they implement the necessary methods defined in the autosec_module.py module'''
    pass
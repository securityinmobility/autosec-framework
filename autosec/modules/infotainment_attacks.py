"""
This module contains several attacks and scans on infotainment interfaces:
- Bluetooth and WiFi: Format string attack via device name
- WiFi, Ethernet or USB: Device and Port scan
- USB: HID simulation
"""
from autosec.core.autosec_module import AutosecModule

__author__: str = "Michael Weichenrieder"


def load_module() -> [AutosecModule]:
    """
    Method to provide the submodules to the framework
    """
    return []  # TODO Add constructor calls to provide module objects

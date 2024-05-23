"""
This module contains resources for serial communication
"""

from autosec.core.ressources import AutosecRessource

__author__: str = "Michael Weichenrieder"


class WirelessFormatstringResult(AutosecRessource):
    """
    A result of a wireless formatstring attack
    """

    def __init__(self, wireless_type: str, formatstring: str, success: bool):
        """
        :param wireless_type: The wireless type used (wlan/bluetooth)
        :param formatstring: The used formatstring
        :param success: True for success, else False
        """
        self._wireless_type: str = wireless_type
        self._formatstring: str = formatstring
        self._success: bool = success

    def get_wireless_type(self) -> str:
        """
        :return: The used wireless_type
        """
        return self._wireless_type

    def get_formatstring(self) -> str:
        """
        :return: The used formatstring
        """
        return self._formatstring

    def get_success(self) -> bool:
        """
        :return: True for success, else False
        """
        return self._success


class KeystrokeInjectionResult(AutosecRessource):
    """
    A result of a keystroke injection attack
    """

    def __init__(self, keyboard_layout: str, injected_command: str, success: bool):
        """
        :param keyboard_layout: The keyboard layout used
        :param injected_command: The injected command
        :param success: True for success, else False
        """
        self._keyboard_layout: str = keyboard_layout
        self._injected_command: str = injected_command
        self._success: bool = success

    def get_keyboard_layout(self) -> str:
        """
        :return: The used keyboard layout
        """
        return self._keyboard_layout

    def get_injected_command(self) -> str:
        """
        :return: The injected command
        """
        return self._injected_command

    def get_success(self) -> bool:
        """
        :return: True for success, else False
        """
        return self._success

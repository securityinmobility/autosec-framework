"""
This module contains resources for serial communication
"""

from autosec.core.ressources import AutosecRessource

__author__: str = "Michael Weichenrieder"


class COMPort(AutosecRessource):
    """
    A COM port
    """

    def __init__(self, port: str):
        """
        :param port: The COM port
        """
        self._port: str = port

    def get_port(self) -> str:
        """
        :return: The COM port
        """
        return self._port

class AutosecRessource:

    """
    Autosec ressource base class
    """

    def get_name(self) -> str:
        """
        :return: The name of the ressource
        """
        return "AutosecRessource {}".format(self.__class__)


class NetworkInterface(AutosecRessource):
    """
    Network interface ressource
    """

    def __init__(self, interface: str):
        """
        :param interface: The interface name
        """
        self._interface_name: str = interface

    def get_interface_name(self) -> str:
        """
        :return: The interface name
        """
        return self._interface_name

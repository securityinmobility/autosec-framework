class AutosecRessource():
    def get_name(self) -> str:
        return "AutosecRessource {}".format(self.__class__)

class NetworkInterface(AutosecRessource):
    _interface_name: str

    def __init__(self, interface: str):
        self._interface_name = interface

    def get_interface_name(self) -> str:
        return self._interface_name

from .base import AutosecRessource

class WifiChannel(AutosecRessource):
    """
    Helperclass that holds the most important information about
    a particlar WifiChannel.
    The tx_power is read out of iw output.
    Enabled is read out of iw output and depends on the driver and regulatory database
    """
    centre_frequency: int = 0       # Carrier centre frequency
    channel_number: int = 0         # Channel number according 802.11 standard
    channel_width: int = 0          # Channel width
    tx_power: float =0              # Ususally measured in dbm
    enabled: bool = False           # State of the channel with respect to the regulatory domain
    #TODO: Implement NL_FLAGS like NO-IR

    def __init__(self) -> None:
        self.centre_frequency = 0
        self.channel_number = 0
        self.channel_width = 0
        self.tx_power = 0
        self.enabled = False

    def set_tx(self, input_text: str):
        """
        Set transmit power value.
        Will be set to 0, if the string reads disables.
        The function parses iw output text
        """
        if "disabled" in input_text:
            self.tx_power = 0
            self.enabled = False
        elif float(input_text) > 0:
            self.tx_power = float(input_text)
            self.enabled = True
        else:
            print("Error parsing input")

class OcbInterface(AutosecRessource):
    _interface_name: str

    def __init__(self, interface: str):
        self._interface_name = interface

    def get_interface_name(self) -> str:
        return self._interface_name
    
class VanetzaInstance(AutosecRessource):
    _launched: str
    _pid: int

class MqttInstance(AutosecRessource):
    _launched: str
    _pid: int
    port: int
    ip : str